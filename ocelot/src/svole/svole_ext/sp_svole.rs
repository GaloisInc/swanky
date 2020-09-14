// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang SpsVole protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        copee::to_fpr,
        svole_ext::{EqReceiver, EqSender, SpsVoleReceiver, SpsVoleSender,
        ggm_utils::{ggm, ggm_prime}
        },
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use num::pow;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_core::RngCore;
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    AesRng,
    Block,
    Malicious,
};
use std::{
    arch::x86_64::*,
    marker::PhantomData,
    ops::{MulAssign, SubAssign},
};
/// SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver + Malicious, FE: FF, SV: SVoleSender, EQ: EqSender> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    pows: Vec<FE>,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender + Malicious, FE: FF, SV: SVoleReceiver, EQ: EqReceiver> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
}



/// Implement SpsVole for Sender type.
impl<
        OT: OtReceiver<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleSender<Msg = FE>,
        EQ: EqSender<Msg = FE>,
    > SpsVoleSender for Sender<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let ot_receiver = OT::init(channel, rng).unwrap();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let svole_sender = SV::init(channel, rng).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _eq: PhantomData::<EQ>,
            pows,
            svole: svole_sender,
            ot: ot_receiver,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        mut rng: &mut RNG,
        len: u128,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let depth = 128 - (len - 1).leading_zeros() as usize;
        let n = len as usize;
        let ac = self.svole.send(channel, 1, rng).unwrap();
        let (a, c): (Vec<FE::PrimeField>, Vec<FE>) = ac.iter().cloned().unzip();
        let g = FE::PrimeField::generator();
        let beta = g.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        let _delta_ = c.clone();
        let mut a_prime = beta.clone();
        a_prime.sub_assign(a[0]);
        channel.write_fe(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut u = vec![FE::PrimeField::zero(); n];
        u[alpha] = beta;
        let choices = unpack_bits(&(!alpha).to_le_bytes(), depth);
        let keys = self.ot.receive(channel, &choices, rng).unwrap();
        let v: Vec<FE> = ggm_prime(alpha, &keys);
        let delta_ = c[0];
        let mut d: FE = channel.read_fe().unwrap();
        let mut w: Vec<FE> = v;
        let sum_w = w.iter().enumerate().filter(|(i, _w)| *i != alpha).fold(
            FE::zero(),
            |mut sum: FE, (_, w)| {
                sum.add_assign(*w);
                sum
            },
        );
        d.add_assign(sum_w);
        w[alpha] = delta_;
        w[alpha].sub_assign(d);
        // Both parties send (extend, r), gets (x, z)
        let xz = self.svole.send(channel, r, rng).unwrap();
        let (x, z): (Vec<FE::PrimeField>, Vec<FE>) = xz.iter().cloned().unzip();
        // Sampling `chi`s.
        let chi: Vec<FE> = (0..n).map(|_| FE::random(&mut rng)).collect();
        let chi_alpha = chi[alpha].to_polynomial_coefficients();
        let x_star: Vec<FE::PrimeField> = chi_alpha
            .iter()
            .zip(x.iter().cloned())
            .map(|(chi, x)| {
                let mut tmp = *chi;
                tmp.mul_assign(beta);
                tmp.sub_assign(x);
                tmp
            })
            .collect();
        // Sends chis and x_star
        for item in chi.iter() {
            channel.write_fe(*item)?;
        }
        for item in x_star.iter() {
            channel.write_fe(*item)?;
        }
        let z_ = z
            .iter()
            .zip(self.pows.iter())
            .fold(FE::zero(), |mut sum, (z, pow)| {
                let mut tmp = *z;
                tmp.mul_assign(*pow);
                sum.add_assign(*z);
                sum
            });
        let mut va = chi
            .iter()
            .zip(w.iter().cloned())
            .fold(FE::zero(), |mut sum, (chi, mut w)| {
                w.mul_assign(*chi);
                sum.add_assign(w);
                sum
            });
        va.sub_assign(z_);
        let mut eq_sender = EQ::init()?;
        let res = eq_sender.send(channel, &va);
        match res {
            Ok(b) => {
                if b {
                    let uw = u.iter().zip(w.iter()).map(|(u, w)| (*u, *w)).collect();
                    Ok(uw)
                } else {
                    return Err(Error::Other("EQ check fails".to_string()));
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Implement SVoleReceiver for Receiver type.
impl<
        OT: OtSender<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleReceiver<Msg = FE>,
        EQ: EqReceiver<Msg = FE>,
    > SpsVoleReceiver for Receiver<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot_sender = OT::init(channel, &mut rng).unwrap();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let sv_receiver = SV::init(channel, rng).unwrap();
        let delta = sv_receiver.delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _eq: PhantomData::<EQ>,
            pows,
            delta,
            ot: ot_sender,
            svole: sv_receiver,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: u128,
    ) -> Result<Vec<FE>, Error> {
        let n = len as usize;
        let depth = 128 - (n - 1).leading_zeros();
        let b = self.svole.receive(channel, 1, rng)?;
        let mut a_prime: FE = channel.read_fe()?;
        let mut gamma = b[0];
        a_prime.mul_assign(self.delta);
        gamma.sub_assign(a_prime);
        // Sample `s` from `$\{0,1\}$`
        let seed = rand::random::<Block>();
        let (v, keys) = ggm(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        channel.flush()?;
        // compute d and sends out
        let sum = v.iter().fold(FE::zero(), |mut sum, v| {
            sum.add_assign(*v);
            sum
        });
        let mut d = gamma.clone();
        d.sub_assign(sum);
        channel.write_fe(a_prime)?;
        channel.flush()?;
        let r = FE::ByteReprLen::to_usize();
        let y_star = self.svole.receive(channel, r, rng).unwrap();
        // Receives `chi`s from the Sender
        let chi: Vec<FE> = (0..n).map(|_| channel.read_fe().unwrap()).collect();
        let x_star: Vec<FE> = (0..r).map(|_| channel.read_fe().unwrap()).collect();
        let y = y_star.clone();
        for (y, mut x) in y.iter().zip(x_star.iter().cloned()) {
            x.mul_assign(self.delta);
            let mut tmp = *y;
            tmp.sub_assign(x);
        }
        // sets Y
        let y_ =
            self.pows
                .iter()
                .zip(y.iter().cloned())
                .fold(FE::zero(), |mut sum, (pow, mut y)| {
                    y.mul_assign(*pow);
                    sum.add_assign(y);
                    sum
                });
        let mut vb = chi
            .iter()
            .zip(v.iter().cloned())
            .fold(FE::zero(), |mut sum, (chi, mut v)| {
                v.mul_assign(*chi);
                sum.add_assign(v);
                sum
            });
        vb.sub_assign(y_);
        let mut eq_receiver = EQ::init().unwrap();
        let res = eq_receiver.receive(channel, rng, &vb);
        match res {
            Ok(b) => {
                if b {
                    Ok(v)
                } else {
                    return Err(Error::Other("EQ check fails".to_string()));
                }
            }
            Err(e) => Err(e),
        }
    }
}

