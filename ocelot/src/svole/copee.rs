// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides implementations of COPEe Traits.

use crate::{
    errors::Error,
    ot::{RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{CopeeReceiver, CopeeSender},
};
use digest::generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use rand::SeedableRng;
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    Aes128,
    AesRng,
    Block,
    Malicious,
};
use std::{
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
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Pack FE into a Vec<FE> whose entries are either `FE::PrimeField::zero()` or
/// `FE::PrimeField::one()`.
#[inline]
pub fn pack_bits_fps<FE: FF>(x: FE) -> Vec<FE::PrimeField> {
    let mut res = Vec::default();
    let r0 = FE::PrimeField::zero();
    let r1 = FE::PrimeField::one();
    let bv = unpack_bits(x.to_bytes().as_slice(), FE::ByteReprLen::to_usize() * 8);
    for i in 0..bv.len() {
        let choice = Choice::from(bv[i] as u8);
        let value = FE::PrimeField::conditional_select(&r0, &r1, choice);
        res.push(value);
    }
    res
}

/// Unpack Vec<FE> into a FE.
#[inline]
pub fn unpack_bits_fps<FE: FF>(x: Vec<FE::PrimeField>) -> FE {
    let mut sum = FE::zero();
    let nbits = FE::ByteReprLen::to_usize() * 8;
    let mut two = FE::one();
    two.add_assign(FE::one());
    for i in 0..nbits {
        let two_ = two.clone();
        let mut powr = two_.pow(i as u128);
        powr.mul_assign(to_fpr(x[i as usize]));
        sum.add_assign(powr);
    }
    sum
}

/// Convert `Fp` to `F(p^r)`
pub fn to_fpr<FE: FF>(x: FE::PrimeField) -> FE {
    let mut data = vec![FE::PrimeField::zero(); FE::PolynomialFormNumCoefficients::to_usize()];
    data[0] = x;
    let g_arr: GenericArray<FE::PrimeField, _> = GenericArray::from_exact_iter(data).unwrap();
    FE::from_polynomial_coefficients(g_arr)
}

/// Convert `F(p^r)` to `F(p)`
pub fn to_fp<FE: FF>(x: FE) -> FE::PrimeField {
    FE::to_polynomial_coefficients(&x)[0]
}
/// Compute dot product `<g,x>`
pub fn g_dotprod<FE: FF>(x: Vec<FE::PrimeField>) -> FE {
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let nbits = FE::ByteReprLen::to_usize() * 8;
    assert_eq!(x.len(), r * nbits);
    let g = FE::PrimeField::generator();
    let mut res = FE::PrimeField::zero();
    let mut two = FE::PrimeField::one();
    two.add_assign(FE::PrimeField::one());

    for i in 0..FE::PolynomialFormNumCoefficients::to_usize() {
        let mut sum = FE::PrimeField::zero();
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
    to_fpr(res)
}

/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious, FE: FF> CopeeSender for Sender<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let nbytes = FE::ByteReprLen::to_usize();
        let samples = ot
            .send_random(
                channel,
                nbytes * 8 * FE::PolynomialFormNumCoefficients::to_usize(),
                &mut rng,
            )
            .unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            sv: samples,
            nbits: nbytes * 8,
        })
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<FE::PrimeField>,
    ) -> Result<Vec<FE>, Error> {
        let mut w = Vec::default();
        for j in 0..input.len() {
            let mut wv = Vec::default();
            for i in 0..self.nbits * FE::PolynomialFormNumCoefficients::to_usize() {
                // Aes encryption as a PRF
                let pt = Block::from(j as u128);
                let key0 = Block::from(self.sv[i].0);
                let cipher0 = Aes128::new(key0);
                let seed0 = cipher0.encrypt(pt);
                let mut rng0 = AesRng::from_seed(seed0);
                let mut w0 = FE::PrimeField::random(&mut rng0);
                let key1 = Block::from(self.sv[i].1);
                let cipher1 = Aes128::new(key1);
                let seed1 = cipher1.encrypt(pt);
                let mut rng1 = AesRng::from_seed(seed1);
                let w1 = FE::PrimeField::random(&mut rng1);
                wv.push((w0, w1));
                (w0.sub_assign(w1));
                w0.sub_assign(input[j]);
                channel.write_bytes(w0.to_bytes().as_slice())?;
            }
            channel.flush()?;
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
        let deltab = unpack_bits(delta.to_bytes().as_slice(), nbytes * 8);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            delta,
            choices: deltab,
            mv: ots,
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
        let mut output = Vec::default();
        let delta_fp = pack_bits_fps(self.delta);
        let nbytes = FE::ByteReprLen::to_usize();
        for j in 0..len {
            let mut v = Vec::default();
            for i in 0..nbytes * 8 * FE::PolynomialFormNumCoefficients::to_usize() {
                let pt = Block::from(j as u128);
                let key = Block::from(self.mv[i]);
                let cipher = Aes128::new(key);
                let seed = cipher.encrypt(pt);
                let mut rng = AesRng::from_seed(seed);
                let mut w_delta = FE::PrimeField::random(&mut rng);
                let mut data = vec![0u8; nbytes];
                channel.read_bytes(&mut data)?;
                let mut tau = FE::PrimeField::from_bytes(GenericArray::from_slice(&data)).unwrap();
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
    use scuttlebutt::{
        field::{FiniteField as FF, Fp},
        AesRng,
    };
    fn bit_composition<FE: FF>() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x = FE::random(&mut rng);
        let bv = pack_bits_fps(x);
        assert_eq!(unpack_bits_fps::<FE>(bv), x);
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
        assert_eq!(g_dotprod::<FE>(pack_bits_fps(x)), x);
    }

    fn to_type_fpr<FE: FF>() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let x = FE::random(&mut rng);
        assert_eq!(to_fpr::<FE>(to_fp(x)), x);
    }
    #[test]
    fn test_to_fpr() {
        to_type_fpr::<Fp>();
    }
}
