// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang COPEe protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 12).

use crate::{
    errors::Error,
    ot::{RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{CopeeReceiver, CopeeSender},
};
//use digest::generic_array::typenum::Unsigned;
use generic_array::{typenum::Unsigned, GenericArray};
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
    iter::FromIterator,
    marker::PhantomData,
    ops::{AddAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable};

/// COPEe sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    keys: Vec<(Block, Block)>,
    pows: Vec<FE>,
    twos: Vec<FE>,
    nbits: usize,
}

/// COPEe receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious, FE: FF> {
    _fe: PhantomData<FE>,
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: Vec<bool>,
    keys: Vec<Block>,
    pows: Vec<FE>,
    twos: Vec<FE>,
    nbits: usize,
}

/// Converts an element of `Fp` to `F(p^r)`.
/// Note that the converted element has the input element as the first component
/// while other components are being `FE::PrimeField::zero()`.
pub fn to_fpr<FE: FF>(x: FE::PrimeField) -> FE {
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    FE::from_polynomial_coefficients(GenericArray::from_iter((0..r).map(|i| {
        FE::PrimeField::conditional_select(
            &FE::PrimeField::zero(),
            &x,
            Choice::from((i == 0) as u8),
        )
    })))
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
        let mut ot = ROT::init(channel, &mut rng)?;
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let keys = ot.send_random(channel, nbits * r, &mut rng)?;
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        acc = FE::one();
        let two = FE::one() + FE::one();
        let mut twos = vec![FE::zero(); nbits];
        for i in 0..nbits {
            twos[i] = acc;
            acc *= two;
        }
        Ok(Self {
            _ot: PhantomData::<ROT>,
            keys,
            nbits,
            pows,
            twos,
        })
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &[FE::PrimeField],
    ) -> Result<Vec<FE>, Error> {
        let mut w = vec![];
        for (i, u) in input.iter().enumerate() {
            let pt = Block::from(i as u128);
            let mut res = FE::zero();
            for (j, pow) in self.pows.iter().enumerate() {
                let mut sum = FE::zero();
                for (k, two) in self.twos.iter().enumerate() {
                    let (k0, k1) = self.keys[j * self.nbits + k];
                    let mut w0 = prf::<FE>(k0, pt);
                    let w1 = prf::<FE>(k1, pt);
                    let mut tmp = to_fpr::<FE>(w0);
                    tmp.mul_assign(*two);
                    sum.add_assign(tmp);
                    w0.sub_assign(w1);
                    w0.sub_assign(*u);
                    channel.write_bytes(&w0.to_bytes())?;
                }
                sum.mul_assign(*pow);
                res.add_assign(sum);
            }
            w.push(res);
        }
        channel.flush()?;
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
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut ot = ROT::init(channel, &mut rng)?;
        let delta = FE::random(&mut rng);
        let choices = unpack_bits(delta.to_bytes().as_slice(), nbits * r);
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        acc = FE::one();
        // `two` is an element from the finite field. For example, `two` becomes `FE::zero()`
        //  when FE is equal to either `F2` or `Gf128`.
        let two = FE::one() + FE::one();
        let mut twos = vec![FE::zero(); nbits];
        for i in 0..nbits {
            twos[i] = acc;
            acc *= two;
        }
        let keys = ot.receive_random(channel, &choices, &mut rng)?;
        Ok(Self {
            _fe: PhantomData::<FE>,
            _ot: PhantomData::<ROT>,
            delta,
            choices,
            pows,
            twos,
            keys,
            nbits,
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
        for i in 0..len {
            let pt = Block::from(i as u128);
            let mut res = FE::zero();
            for (j, pow) in self.pows.iter().enumerate() {
                let mut sum = FE::zero();
                for (k, two) in self.twos.iter().enumerate() {
                    let w = prf::<FE>(self.keys[j * self.nbits + k], pt);
                    let mut tau = channel.read_fe::<FE::PrimeField>()?;
                    let choice = Choice::from(self.choices[j + k] as u8);
                    tau.add_assign(w);
                    let v = FE::PrimeField::conditional_select(&w, &tau, choice);
                    let mut tmp = to_fpr::<FE>(v);
                    tmp.mul_assign(*two);
                    sum.add_assign(tmp);
                }
                sum.mul_assign(*pow);
                res.add_assign(sum);
            }
            output.push(res);
        }
        Ok(output)
    }
}
