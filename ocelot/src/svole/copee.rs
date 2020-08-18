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
use digest::generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use num::pow;
use rand::SeedableRng;
use scuttlebutt::utils::unpack_bits;
use scuttlebutt::{
    field::{FiniteField as FF, Fp},
    AbstractChannel, Aes128, AesRng, Block, Malicious,
};
use std::convert::TryInto;
use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable};

/// A COPEe Sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious, FE: FF> {
    _fe: PhantomData<FE>,
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
    nbits: usize,
}

/// A COPEe Receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious, FE: FF> {
    _fe: PhantomData<FE>,
    _ot: PhantomData<ROT>,
    delta: FE,
    nbits: usize,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Convert Fp into a bit-vector.
/*#[inline]
pub fn fp_to_bv<FE:FF>(x: FE) -> Vec<bool> {
    let n = x.to_bytes();
    let nbits = FE::ByteReprLen::to_u64()*8;
    for i in n.iter(){
        !(n & (1 << i) == 0)
    }
    (0..nbits).map(|i| !(n & (1 << i) == 0)).collect()
}

/// Convert bit-vector into a Fp.
#[inline]
pub fn bv_to_fp(bv: Vec<bool>) -> Fp {
    let res = (0..128).fold(0, |sum, i| sum + (pow(2, i) * (u128::from(bv[i]))));
    Fp::try_from(res).unwrap()
}
*/
/// Convert Fp into a Vec<Fp>.
#[inline]
pub fn pack_bits_fps<FE: FF>(x: FE) -> Vec<FE> {
    let mut res = Vec::new();
    let r0 = FE::zero();
    let r1 = FE::one();
    let bv = unpack_bits(x.to_bytes().as_slice(), FE::ByteReprLen::to_usize() * 8);
    for i in 0..bv.len() {
        let choice = Choice::from(bv[i] as u8);
        let value = FE::conditional_select(&r0, &r1, choice);
        res.push(value);
    }
    res
}

/// Convert Vec<Fp> into a Fp
#[inline]
pub fn unpack_bits_fps<FE: FF>(x: Vec<FE>) -> FE {
    let mut sum = FE::zero();
    let nbits = FE::ByteReprLen::to_usize() * 8;
    let mut two = FE::one();
    two.add_assign(FE::one());
    for i in 0..nbits {
        let two_ = two.clone();
        let mut powr = two_.pow(i as u128);
        powr.mul_assign(x[i as usize]);
        sum.add_assign(powr);
    }
    sum
}

/// Compute <g, x>.
pub fn g_dotprod<FE: FF>(x: Vec<FE>) -> FE {
    let g = FE::generator();
    let mut res = FE::zero();
    let mut two = FE::one();
    two.add_assign(FE::one());
    let nbits = FE::ByteReprLen::to_usize() * 8;
    for i in 0..Params::R {
        let mut sum = FE::zero();
        for j in 0..nbits {
            let temp = two.clone();
            let mut powr = temp.pow(j as u128);
            powr.mul_assign(x[(i * nbits) + j]);
            sum.add_assign(powr);
        }
        let powg = g.pow(i as u128);
        sum.mul_assign(powg);
        res.add_assign(sum);
    }
    res
}

/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious, FE: FF> CopeeSender for Sender<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        /// Combine step 1 and 2 and by calling ROT.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let nbits = FE::ByteReprLen::to_usize() * 8;
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let samples = ot
            .send_random(channel, nbits * Params::R, &mut rng)
            .unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            sv: samples,
            nbits,
        })
    }
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<FE>,
    ) -> Result<Vec<FE>, Error> {
        let mut w: Vec<FE> = Vec::new();
        for j in 0..input.len() {
            /// Step 3.
            let mut wv: Vec<(FE, FE)> = Vec::new();
            for i in 0..self.nbits * Params::R {
                /// Aes encryption as a PRF
                let pt = Block::from(j as u128);
                let key0 = Block::from(self.sv[i].0);
                let cipher0 = Aes128::new(key0);
                let seed0 = cipher0.encrypt(pt);
                let mut rng0 = AesRng::from_seed(seed0);
                let mut w0 = FE::random(&mut rng0);
                let key1 = Block::from(self.sv[i].1);
                let cipher1 = Aes128::new(key1);
                let seed1 = cipher1.encrypt(pt);
                let mut rng1 = AesRng::from_seed(seed1);
                let w1 = FE::random(&mut rng1);
                wv.push((w0, w1));
                (w0.sub_assign(w1));
                w0.sub_assign(input[j]);
                channel.write_bytes(w0.to_bytes().as_slice())?;
            }
            w.push(g_dotprod(wv.into_iter().map(|x| x.0).collect()));
        }
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<ROT: ROTReceiver<Msg = Block> + Malicious, FE: FF> CopeeReceiver for Receiver<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let nbytes = FE::ByteReprLen::to_usize();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let delta = FE::random(&mut rng);
        let deltab = unpack_bits(delta.to_bytes().as_slice(), nbytes);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        let nbits = FE::ByteReprLen::to_usize() * 8;
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            delta,
            choices: deltab,
            mv: ots,
            nbits,
        })
    }
    fn get_delta(&self) -> FE {
        self.delta
    }
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<FE>, Error> {
        let mut output: Vec<FE> = Vec::new();
        let delta_fp = pack_bits_fps(self.delta);
        let nbytes = FE::ByteReprLen::to_usize();
        for j in 0..len {
            let mut v: Vec<FE> = Vec::new();
            for i in 0..self.nbits * Params::R {
                let pt = Block::from(j as u128);
                let key = Block::from(self.mv[i]);
                let cipher = Aes128::new(key);
                let seed = cipher.encrypt(pt);
                let mut rng = AesRng::from_seed(seed);
                let mut w_delta = FE::random(&mut rng);
                let mut data = vec![0u8; nbytes];
                channel.read_bytes(&mut data)?;
                let mut tau = FE::from_bytes(GenericArray::from_slice(&data)).unwrap();
                tau.mul_assign(delta_fp[i]);
                w_delta.add_assign(tau);
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
    use scuttlebutt::field::{FiniteField as FF, Fp, Gf128};
    use scuttlebutt::AesRng;
    fn bit_composition<FE: FF>() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x = FE::random(&mut rng);
        let bv = pack_bits_fps(x);
        assert_eq!(unpack_bits_fps(bv), x);
    }
    #[test]
    fn test_bit_composition() {
        bit_composition::<Fp>();
    }

    #[test]
    fn test_g_dotproduct() {
        g_dotproduct::<Fp>();
    }
    fn g_dotproduct<FE: FF>() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x = FE::random(&mut rng);
        assert_eq!(g_dotprod(pack_bits_fps(x)), x);
    }
}
