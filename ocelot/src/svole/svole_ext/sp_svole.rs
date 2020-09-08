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
        svole_ext::{SpsVoleReceiver, SpsVoleSender},
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng, SeedableRng};
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

// Define static variable
lazy_static! {
    static ref ZERO: __m128i = unsafe { _mm_setzero_si128() };
}

/// SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver + Malicious, FE: FF, SV: SVoleSender> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    svole: SV,
    ot: OT,
    pows: Vec<FE>,
    nbits: usize,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender + Malicious, FE: FF, SV: SVoleReceiver> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    svole: SV,
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
    nbits: usize,
}

/// The input vector length `n` may be included in the arguments
pub fn ggm<FE: FF, RNG: CryptoRng + Rng>(kappa: u128, seed: Block, mut rng:&mut RNG) -> (Vec<FE>, Vec<(Block, Block)>) {
    let sv = Vec::new();
    sv.push(seed);
    let h = 128 - (kappa - 1).leading_zeros() as usize;
    for i in 1..h{
        for j in 0..2 ^ (i - 1) {
            let s = sv[i - 1 + j].clone();
            //PRG G
            let mut rng = AesRng::from_seed(s);
            let (s0, s1) = rng.gen::<(Block, Block)>();
            sv.push(s0);
            sv.push(s1);
        }
    }
    let v = Vec::new();
    // compute vector `v` at last level 
    for j in 0..2 ^ (h-1) {
        let temp = sv[h + j].clone();
        // PRG G'
        let mut rng = AesRng::from_seed(temp);
        let (fe0, fe1) = (FE::random(&mut rng), FE::random(&mut rng));
        v.push(fe0);
        v.push(fe1);
    }
    // remove first seed from sv
    sv.remove(0);
    // TODO: optimize this later
   let vec_even: Vec<Block> = sv.iter().step_by(2).map(|u| u).collect(); 
   let vec_odd = sv.iter().skip(1).step_by(2).map(|u| u).collect(); 
   let zip_seeds = vec_even.iter().zip(vec_odd.iter());
   let mut k0: Vec<Block> = Vec::new();
   let mut k1: Vec<Block> = Vec::new();
   for i in 1..h+1{
    let mut res0 = Block(*ZERO);
    let mut res1 = Block(*ZERO); 
    for j in 0..2 ^ (i - 1){
      res0 ^= zip_seeds[j+2 ^ (i - 1)-1].0;
      res1 ^= zip_seeds[j+2 ^ (i - 1)-1].1;
    }
    k0.push(res0);
    k1.push(res1);
}
let keys = k0.iter().zip(k1.iter());
(v, keys)
}

pub fn ggm_prime<FE: FF>(alpha: usize, ots: Vec<Block>) -> Vec<FE> {
    // TODO: fix this later
    let mut v: Vec<FE> = (0..n)
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
impl<OT: OtReceiver<Msg = Block> + Malicious, FE: FF, SV: SVoleSender<Msg = FE>> SpsVoleSender
    for Sender<OT, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut ot_receiver = OT::init(channel, rng).unwrap();
        let pows = (0..r).map(|j| g.pow(j as u128)).collect();
        let svole_sender = SV::init(channel, rng).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            pows,
            nbits,
            svole: svole_sender,
            ot: ot_receiver,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        exp_h: usize,
    ) -> Result<(Vec<FE::PrimeField>, Vec<FE>), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let n = 2 ^ exp_h;
        let (a, c) = self.svole.send(channel, 1, rng).unwrap();
        let g = FE::PrimeField::generator();
        let beta = g.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        let delta_ = c;
        let mut a_prime = beta.clone();
        a_prime.sub_assign(a[0]);
        channel.write_fe(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut u = vec![FE::PrimeField::zero(); n];
        u[alpha] = beta;
        let mut choices = unpack_bits(&(!alpha).to_le_bytes(), exp_h);
        let keys = self.ot.receive(channel, &choices, rng).unwrap();
        let v: Vec<FE> = ggm_prime(alpha, keys);
        let delta_ = c[0];
        let mut d: FE = channel.read_fe().unwrap();
        let mut w: Vec<FE> = v;
        let sum_w = w.iter().enumerate().filter(|(i, w)| *i != alpha).fold(
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
        let (x, z): (Vec<FE::PrimeField>, Vec<FE>) = self.svole.send(channel, r, rng).unwrap();
        // Sampling `chi`s.
        let mut chi: Vec<FE> = (0..n).map(|_| FE::random(&mut rng)).collect();
        let mut chi_alpha = chi[alpha].to_polynomial_coefficients();
        let x_star: Vec<FE::PrimeField> = chi_alpha
            .iter()
            .zip(x.iter())
            .map(|(chi, &x)| {
                chi.mul_assign(beta);
                chi.sub_assign(x);
                *chi
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
                z.mul_assign(*pow);
                sum.add_assign(*z);
                sum
            });
        let mut va = chi
            .iter()
            .zip(w.iter())
            .fold(FE::zero(), |mut sum, (chi, w)| {
                chi.mul_assign(*w);
                sum.add_assign(*chi);
                sum
            });
        va.sub_assign(z_);
        Ok((u, w))
    }
}
/// Implement SVoleReceiver for Receiver type.
impl<OT: OtSender<Msg = Block> + Malicious, FE: FF, SV: SVoleReceiver<Msg = FE>> SpsVoleReceiver
    for Receiver<OT, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot_sender = OT::init(channel, &mut rng).unwrap();
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::generator();
        let pows = (0..r).map(|j| g.pow(j as u128)).collect();
        let sv_receiver = SV::init(channel, rng).unwrap();
        let delta = sv_receiver.delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            nbits,
            pows,
            delta,
            ot: ot_sender,
            svole: sv_receiver,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        exp_h: usize,
    ) -> Result<Option<Vec<FE>>, Error> {
        let mut b = Vec::default();
        if let Some(b_) = self.svole.receive(channel, 1, rng).unwrap() {
            b = b_;
        }
        let n = 2 ^ exp_h;
        let a_prime: FE = channel.read_fe().unwrap();
        let mut gamma = b[0];
        a_prime.mul_assign(self.delta);
        gamma.sub_assign(a_prime);
        // Sample `s` from `$\{0,1\}$`
        let seed = rand::random::<Block>();
        let (v, keys) = ggm(2 ^ n - 1, seed);
        self.ot.send(channel, &keys, &mut rng)?;
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
        let mut y_star = Vec::default();
        if let Some(y) = self.svole.receive(channel, r, rng).unwrap() {
            y_star = y;
        }
        // Receives `chi`s from the Sender
        let mut chi: Vec<FE> = (0..n).map(|_| channel.read_fe().unwrap()).collect();
        let mut x_star: Vec<FE> = (0..r).map(|_| channel.read_fe().unwrap()).collect();
        let mut y = y_star.clone();
        for (y, x) in y.iter().zip(x_star.iter()) {
            x.mul_assign(self.delta);
            y.sub_assign(*x);
        }
        // sets Y
        let g = FE::generator();
        let y_ = self
            .pows
            .iter()
            .zip(y.iter())
            .fold(FE::zero(), |mut sum, (pow, y)| {
                y.mul_assign(*pow);
                sum.add_assign(*y);
                sum
            });
        let mut vb = chi
            .iter()
            .zip(v.iter())
            .fold(FE::zero(), |mut sum, (chi, v)| {
                chi.mul_assign(*v);
                sum.add_assign(*chi);
                sum
            });
        vb.sub_assign(y_);
        Ok(None)
    }
}
