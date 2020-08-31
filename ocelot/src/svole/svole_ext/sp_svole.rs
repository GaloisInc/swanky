// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Single-point Subfield Vector Oblivious Linear-function Evaluation (SpsVole)
//!
//! This module provides implementations of SpsVole Traits.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        copee::to_fpr,
        svole_ext::{Params, SpsVoleReceiver, SpsVoleSender},
        CopeeReceiver,
        CopeeSender,
        SVoleReceiver,
        SVoleSender,
    },
};
use digest::generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use rand::{Rng, SeedableRng};
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    AesRng,
    Block,
    Malicious,
};
use std::{
    marker::PhantomData,
    ops::{MulAssign, SubAssign},
};

/// A SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver + Malicious, CP: CopeeSender, FE: FF, SV: SVoleSender> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    svole: SV,
}

/// A SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender + Malicious, CP: CopeeReceiver, FE: FF, SV: SVoleReceiver> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    delta: FE,
    svole: SV,
}
/// The input vector length `n` may be included in the arguments
pub fn ggm<FE: FF>(kappa: usize, seed: Block) -> (Vec<FE>, Vec<(Block, Block)>) {
    let mut rng = AesRng::from_seed(seed);
    let n = (kappa as f32 + 1.0).log(2.0);
    assert_eq!(n as usize, Params::N);
    let v = (0..n as usize).map(|_| FE::random(&mut rng)).collect();
    let h = n.log(2.0);
    let pair_blocks = (0..h as usize)
        .map(|_| rand::random::<(Block, Block)>())
        .collect();
    (v, pair_blocks)
}

pub fn ggm_prime<FE: FF>(alpha: usize, ots: Vec<Block>) -> Vec<FE> {
    // TODO: fix this later
    let mut v: Vec<FE> = (0..Params::N)
        .map(|i| {
            let mut rng = AesRng::from_seed(ots[i]);
            FE::random(&mut rng)
        })
        .collect();
    v.remove(alpha - 1);
    v
}

/// dot product

/// Implement SpsVole for Sender type.
impl<
        OT: OtReceiver<Msg = Block> + Malicious,
        FE: FF,
        CP: CopeeSender<Msg = FE>,
        SV: SVoleSender<Msg = FE>,
    > SpsVoleSender for Sender<OT, CP, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let vsender = SV::init(channel).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            svole: vsender,
        })
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<(Vec<FE::PrimeField>, Vec<FE>), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let (a, c) = self.svole.send(channel).unwrap();
        let g = FE::PrimeField::generator();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let beta = g.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        // Sends out a'=\beta-a
        let mut a_prime = beta.clone();
        a_prime.sub_assign(a[0]);
        channel.write_bytes(a_prime.to_bytes().as_slice())?;
        // Samples \alpha in [0,n)
        let alpha = rng.gen_range(0, Params::N);
        let mut u = vec![FE::PrimeField::zero(); Params::N];
        u[alpha] = beta;
        // bool vec for alpha
        let mut alpha_bv = unpack_bits(&alpha.to_le_bytes(), Params::H);
        // flip bits
        for i in 0..alpha_bv.len() {
            alpha_bv[i] = !alpha_bv[i];
        }
        let mut ot_receiver = OT::init(channel, &mut rng).unwrap();
        let ots = ot_receiver.receive(channel, &alpha_bv, &mut rng).unwrap();
        let v: Vec<FE> = ggm_prime(alpha, ots);
        let delta_ = c[0];
        let nbytes = FE::ByteReprLen::to_usize();
        let mut data = vec![0u8; nbytes];
        channel.read_bytes(&mut data).unwrap();
        let mut d = FE::from_bytes(GenericArray::from_slice(&data)).unwrap();
        let mut w: Vec<FE> = (0..Params::N)
            .map(|i| if i != alpha { v[i] } else { FE::zero() })
            .collect();
        let sum_w = (0..Params::N)
            .filter(|i| *i != alpha)
            .fold(FE::zero(), |mut sum: FE, i| {
                sum.add_assign(w[i]);
                sum
            });
        d.add_assign(sum_w);
        w[alpha] = delta_;
        w[alpha].sub_assign(d);
        // Both parties send (extend, r), gets (x, z)
        let (x, z): (Vec<_>, Vec<FE>) = self.svole.send(channel).unwrap();
        // Sampling `chi`s.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut chi: Vec<FE> = (0..Params::N).map(|_| FE::random(&mut rng)).collect();
        let mut chi_poly_coeffs = chi[alpha].to_polynomial_coefficients();
        let x_star: Vec<FE> = (0..r)
            .map(|i| {
                chi_poly_coeffs[i].mul_assign(beta);
                chi_poly_coeffs[i].sub_assign(x[i]);
                to_fpr(chi_poly_coeffs[i])
            })
            .collect();
        // Sends chis and x_star
        for item in chi.iter() {
            channel.write_bytes(item.to_bytes().as_slice())?;
        }
        for item in x_star.iter() {
            channel.write_bytes(item.to_bytes().as_slice())?;
        }
        let zee = (0..r).fold(FE::zero(), |mut sum, i| {
            let g_i = g.pow(i as u128);
            let mut temp = z[i].clone();
            temp.mul_assign(to_fpr(g_i));
            sum.add_assign(temp);
            sum
        });
        let mut va = (0..Params::N).fold(FE::zero(), |mut sum, i| {
            chi[i].mul_assign(w[i]);
            sum.add_assign(chi[i]);
            sum
        });
        va.sub_assign(zee);
        Ok((u, w))
    }
}
/// Implement SVoleReceiver for Receiver type.
impl<
        OT: OtSender<Msg = Block> + Malicious,
        FE: FF,
        CP: CopeeReceiver<Msg = FE>,
        SV: SVoleReceiver<Msg = FE>,
    > SpsVoleReceiver for Receiver<OT, CP, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let sv = SV::init(channel).unwrap();
        let delta = sv.get_delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            svole: sv,
            delta,
        })
    }

    fn get_delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Option<Vec<FE>>, Error> {
        let mut b = Vec::default();
        if let Some(b_) = self.svole.receive(channel).unwrap() {
            b = b_;
        }
        let nbytes =
            <<FE as scuttlebutt::field::FiniteField>::PrimeField as FF>::ByteReprLen::to_usize();
        // receive a_prime from the sender
        let mut data_a = vec![0u8; nbytes];
        channel.read_bytes(&mut data_a).unwrap();
        let mut a_prime: FE =
            to_fpr(FE::PrimeField::from_bytes(GenericArray::from_slice(&data_a)).unwrap());
        // compute gamma
        let mut gamma = b[0];
        a_prime.mul_assign(self.delta);
        gamma.sub_assign(a_prime);
        // Sample `s` from `$\{0,1\}$`
        let seed = rand::random::<Block>();
        let (v, ot_pairs) = ggm(2 ^ (Params::N) - 1, seed);
        let mut rng = AesRng::from_seed(seed);
        let mut ot_sender = OT::init(channel, &mut rng).unwrap();
        ot_sender.send(channel, &ot_pairs, &mut rng)?;
        channel.flush()?;
        // compute d and sends out
        let sum = (0..Params::N).fold(FE::zero(), |mut sum, i| {
            sum.add_assign(v[i]);
            sum
        });
        let mut d = gamma.clone();
        d.sub_assign(sum);
        channel.write_bytes(a_prime.to_bytes().as_slice())?;
        channel.flush()?;
        let r = FE::ByteReprLen::to_usize();
        let mut y_star = Vec::default();
        if let Some(y) = self.svole.receive(channel).unwrap() {
            y_star = y;
        }
        // Receives `chi`s from the Sender
        let mut chi: Vec<FE> = (0..Params::N)
            .map(|_| {
                let mut data = vec![0u8; nbytes];
                channel.read_bytes(&mut data).unwrap();
                FE::from_bytes(GenericArray::from_slice(&data)).unwrap()
            })
            .collect();
        let mut x_star: Vec<FE> = (0..r)
            .map(|_| {
                let mut data = vec![0u8; nbytes];
                channel.read_bytes(&mut data).unwrap();
                FE::from_bytes(GenericArray::from_slice(&data)).unwrap()
            })
            .collect();
        let mut y = y_star.clone();
        for i in 0..r {
            x_star[i].mul_assign(self.delta);
            y[i].sub_assign(x_star[i]);
        }
        // sets Y
        let g = FE::generator();
        let y_ = (0..r).fold(FE::zero(), |mut sum, i| {
            let g_pow_i = g.pow(i as u128);
            y[i].mul_assign(g_pow_i);
            sum.add_assign(y[i]);
            sum
        });
        let mut vb = (0..Params::N).fold(FE::zero(), |mut sum, i| {
            chi[i].mul_assign(v[i]);
            sum.add_assign(chi[i]);
            sum
        });
        vb.sub_assign(y_);
        Ok(None)
    }
}
