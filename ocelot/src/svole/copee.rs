// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang COPEe protocol (cf.
//! <https://eprint.iacr.org/2020/925>).

use crate::{
    errors::Error,
    ot::{RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{CopeeReceiver, CopeeSender},
};
use digest::generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use rand::{CryptoRng, Rng, SeedableRng};
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
    ops::{AddAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable};

/// COPEe sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious, FE: FF> {
    _fe: PhantomData<FE>,
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
    nbits: usize,
}

/// COPEe receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious, FE: FF> {
    _fe: PhantomData<FE>,
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Convert `Fp` to `F(p^r)`
pub fn to_fpr<FE: FF>(x: FE::PrimeField) -> FE {
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let mut data = vec![FE::PrimeField::zero(); r];
    data[0] = x;
    let g_arr =
        GenericArray::<FE::PrimeField, FE::PolynomialFormNumCoefficients>::from_exact_iter(data)
            .unwrap();
    FE::from_polynomial_coefficients(g_arr)
}

fn prf<FE: FF>(key: Block, pt: Block) -> FE::PrimeField {
    let aes = Aes128::new(key);
    let seed = aes.encrypt(pt);
    let mut rng = AesRng::from_seed(seed);
    FE::PrimeField::random(&mut rng)
}

/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious, FE: FF> CopeeSender for Sender<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let nbits = FE::MODULUS_NBITS as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let samples = ot.send_random(channel, nbits * r, &mut rng).unwrap();
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
        input: &[FE::PrimeField],
    ) -> Result<Vec<FE>, Error> {
        let mut w = Vec::default();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::generator();
        let mut two = FE::one();
        two.add_assign(FE::one());
        for (i, u) in input.iter().enumerate() {
            let mut res = FE::zero();
            for j in 0..r {
                let mut sum = FE::zero();
                for k in 0..self.nbits {
                    // Aes encryption as a PRF
                    let pt = Block::from(i as u128);
                    let mut w0 = prf::<FE>(self.sv[j * self.nbits + k].0, pt);
                    let w1 = prf::<FE>(self.sv[j * self.nbits + k].1, pt);
                    let tmp = two.pow(k as u128);
                    let mut powr = FE::conditional_select(
                        &tmp,
                        &FE::one(),
                        Choice::from((self.nbits == 1) as u8),
                    );
                    powr.mul_assign(to_fpr(w0));
                    sum.add_assign(powr);
                    w0.sub_assign(w1);
                    w0.sub_assign(*u);
                    channel.write_bytes(&w0.to_bytes())?;
                    channel.flush()?;
                }
                let powg = g.pow(j as u128);
                sum.mul_assign(powg);
                res.add_assign(sum);
            }
            w.push(res);
        }
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<ROT: ROTReceiver<Msg = Block> + Malicious, FE: FF> CopeeReceiver for Receiver<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let nbits = FE::MODULUS_NBITS as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let delta = FE::random(&mut rng);
        let choices = unpack_bits(delta.to_bytes().as_slice(), nbits * r);
        let mv = ot.receive_random(channel, &choices, &mut rng).unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            delta,
            choices,
            mv,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<FE>, Error> {
        let mut output = Vec::default();
        let nbits = FE::MODULUS_NBITS as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut two = FE::one();
        two.add_assign(FE::one());
        let g = FE::generator();
        for i in 0..len {
            let mut res = FE::zero();
            for j in 0..r {
                let mut sum = FE::zero();
                for k in 0..nbits {
                    let pt = Block::from(i as u128);
                    let w_delta = prf::<FE>(self.mv[j * nbits + k], pt);
                    let mut tau: FE::PrimeField = channel.read_sub_fe::<FE>().unwrap();
                    let choice = Choice::from(self.choices[j * nbits + k] as u8);
                    tau.add_assign(w_delta);
                    let v = FE::PrimeField::conditional_select(&w_delta, &tau, choice);
                    let tmp = two.pow(k as u128);
                    let mut powr =
                        FE::conditional_select(&tmp, &FE::one(), Choice::from((nbits == 1) as u8));
                    powr.mul_assign(to_fpr(v));
                    sum.add_assign(powr);
                }
                let powg = g.pow(j as u128);
                sum.mul_assign(powg);
                res.add_assign(sum);
            }
            output.push(res);
        }
        Ok(output)
    }
}
