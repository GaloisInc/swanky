// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides implementations of COPEe Traits.

#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{CopeeReceiver, CopeeSender, Params},
};
use num::pow;
use rand::SeedableRng;
use scuttlebutt::{
    field::{FiniteField as FF, Fp},
    AbstractChannel, Aes128, AesRng, Block, Malicious,
};
use subtle::{Choice, ConditionallySelectable};

use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{AddAssign, MulAssign, SubAssign},
};

/// A COPEe Sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious> {
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
}

/// A COPEe Receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious> {
    _ot: PhantomData<ROT>,
    delta: Fp,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Convert Fp into a bit-vector.
#[inline]
pub fn fp_to_bv(x: Fp) -> Vec<bool> {
    let n = u128::from(x);
    (0..128).map(|i| !(n & (1 << i) == 0)).collect()
}

/// Convert bit-vector into a Fp.
#[inline]
pub fn bv_to_fp(bv: Vec<bool>) -> Fp {
    let res = (0..128).fold(0, |sum, i| sum + (pow(2, i) * (u128::from(bv[i]))));
    Fp::try_from(res).unwrap()
}

/// Convert Vec<bool> into a Vec<Fp>.
#[inline]
pub fn fp_to_bvfp(x: Fp) -> Vec<Fp> {
    let mut res = Vec::new();
    let r0 = FF::zero();
    let r1 = FF::one();
    let n = u128::from(x);
    for i in 0..128 {
        let choice = Choice::from(!(n & (1 << i) == 0) as u8);
        let value = Fp::conditional_select(&r0, &r1, choice);
        res.push(value);
    }
    res
}

/// Convert Vec<Fp> into a Fp
#[inline]
pub fn bvfp_to_fp(x: Vec<Fp>) -> Fp {
    let mut sum: Fp = FF::zero();
    for i in 0..128 {
        let two = Fp::try_from(2).unwrap();
        let mut powr = two.pow(i as u128);
        powr.mul_assign(&x[i]);
        sum.add_assign(&powr);
    }
    sum
}

/// Compute <g, x>.
pub fn g_dotprod(x: Vec<Fp>) -> Fp {
    let g: Fp = FF::generator();
    let mut res: Fp = FF::zero();
    for i in 0..Params::R {
        let mut sum: Fp = FF::zero();
        for j in 0..Params::M {
            let two = Fp::try_from(2).unwrap();
            let mut powr = two.pow(j as u128);
            powr.mul_assign(&x[(i * Params::M) + j]);
            sum.add_assign(&powr);
        }
        let powg = g.pow(i as u128);
        sum.mul_assign(&powg);
        res.add_assign(&sum);
    }
    res
}

/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious> CopeeSender for Sender<ROT> {
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        /// Combine step 1 and 2 and by calling ROT.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let samples = ot
            .send_random(channel, Params::M * Params::R, &mut rng)
            .unwrap();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            sv: samples,
        })
    }
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<Fp>,
    ) -> Result<Vec<Fp>, Error> {
        let mut w: Vec<Fp> = Vec::new();
        for j in 0..input.len() {
            /// Step 3.
            let mut wv: Vec<(Fp, Fp)> = Vec::new();
            for i in 0..Params::M * Params::R {
                /// Aes encryption as a PRF
                let pt = Block::from(j as u128);
                let key0 = Block::from(self.sv[i].0);
                let cipher0 = Aes128::new(key0);
                let mut w0 = Fp::try_from(u128::from(cipher0.encrypt(pt))).unwrap();
                let key1 = Block::from(self.sv[i].1);
                let cipher1 = Aes128::new(key1);
                let w1 = Fp::try_from(u128::from(cipher1.encrypt(pt))).unwrap();
                wv.push((w0, w1));
                (w0.sub_assign(&w1));
                w0.sub_assign(&input[j]);
                channel.write_bytes(w0.to_bytes().as_slice())?;
            }
            w.push(g_dotprod(wv.into_iter().map(|x| x.0).collect()));
        }
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<ROT: ROTReceiver<Msg = Block> + Malicious> CopeeReceiver for Receiver<ROT> {
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let delta: Fp = Fp::random(&mut rng);
        let deltab: Vec<bool> = fp_to_bv(delta);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            delta,
            choices: deltab,
            mv: ots,
        })
    }
    fn get_delta(&self) -> Fp {
        self.delta
    }
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<Fp>, Error> {
        let mut output: Vec<Fp> = Vec::new();
        let delta_fp = fp_to_bvfp(self.delta);
        for j in 0..len {
            let mut v: Vec<Fp> = Vec::new();
            for i in 0..Params::M * Params::R {
                let pt = Block::from(j as u128);
                let key = Block::from(self.mv[i]);
                let cipher = Aes128::new(key);
                let mut w_delta = Fp::try_from(cipher.encrypt(pt)).unwrap();
                let mut data = [0u8; 16];
                channel.read_bytes(&mut data)?;
                let mut tau = Fp::try_from(u128::from_le_bytes(data)).unwrap();
                tau.mul_assign(&delta_fp[i]);
                w_delta.add_assign(&tau);
                v.push(w_delta);
            }
            output.push(g_dotprod(v));
        }
        Ok(output)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::field::{FiniteField as FF, Fp};
    use scuttlebutt::AesRng;

    #[test]
    fn test_bit_composition() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x: Fp = FF::random(&mut rng);
        let bv = fp_to_bv(x);
        assert_eq!(bv_to_fp(bv), x);
    }
    #[test]
    fn test_bvfp_to_fp() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x: Fp = FF::random(&mut rng);
        assert_eq!(bvfp_to_fp(fp_to_bvfp(x)), x);
    }
    #[test]
    fn test_g_dotproduct() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x: Fp = FF::random(&mut rng);
        assert_eq!(g_dotprod(fp_to_bvfp(x)), x)
    }
}
