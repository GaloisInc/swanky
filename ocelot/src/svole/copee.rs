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
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    Aes128,
    Block,
    Malicious,
};
use std::marker::PhantomData;

use subtle::{Choice, ConditionallySelectable};

/// COPEe sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    aes_objs: Vec<(Aes128, Aes128)>,
    pows: Vec<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

/// COPEe receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: Vec<bool>,
    aes_objs: Vec<Aes128>,
    pows: Vec<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

/// `Aes128` as a pseudo-random function.
fn prf<FE: FF>(aes: &Aes128, pt: Block) -> FE::PrimeField {
    let seed = aes.encrypt(pt);
    FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(seed))
}

/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious, FE: FF> CopeeSender for Sender<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = ROT::init(channel, &mut rng)?;
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let keys = ot.send_random(channel, nbits * r, &mut rng)?;
        let aes_objs: Vec<(Aes128, Aes128)> = keys
            .iter()
            .map(|(k0, k1)| (Aes128::new(*k0), Aes128::new(*k1)))
            .collect();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        acc = FE::ONE;
        // `two` can be computed by adding `FE::ONE` to itself. For example, the field `F2` has only two elements `0` and `1`
        // and `two` becomes `0` as `1 + 1 = 0` in this field.
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut().take(nbits) {
            *item = acc;
            acc *= two;
        }
        Ok(Self {
            _ot: PhantomData::<ROT>,
            aes_objs,
            nbits,
            pows,
            twos,
            counter: 0,
        })
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &FE::PrimeField,
    ) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut w = FE::ZERO;
        for (j, pow) in self.pows.iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let (prf0, prf1) = &self.aes_objs[j * self.nbits + k];
                let w0 = prf::<FE>(prf0, pt);
                let w1 = prf::<FE>(prf1, pt);
                sum += two.multiply_by_prime_subfield(w0);
                channel.write_fe(w0 - w1 - *input)?;
            }
            //channel.flush()?;
            sum *= *pow;
            w += sum;
        }
        self.counter += 1;
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<ROT: ROTReceiver<Msg = Block> + Malicious, FE: FF> CopeeReceiver for Receiver<ROT, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let g = FE::GENERATOR;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut ot = ROT::init(channel, &mut rng)?;
        let delta = FE::random(&mut rng);
        let choices = unpack_bits(delta.to_bytes().as_slice(), nbits * r);
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        acc = FE::ONE;
        // `two` can be computed by adding `FE::ONE` to itself. For example, the field `F2` has only two elements `0` and `1`
        // and `two` becomes `0` as `1 + 1 = 0` in this field.
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut().take(nbits) {
            *item = acc;
            acc *= two;
        }
        let keys = ot.receive_random(channel, &choices, &mut rng)?;
        let aes_objs = keys.iter().map(|k| Aes128::new(*k)).collect();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            delta,
            choices,
            pows,
            twos,
            aes_objs,
            nbits,
            counter: 0,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut res = FE::ZERO;
        for (j, pow) in self.pows.iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let w = prf::<FE>(&self.aes_objs[j * self.nbits + k], pt);
                let mut tau = channel.read_fe::<FE::PrimeField>()?;
                let choice = Choice::from(self.choices[j + k] as u8);
                tau += w;
                let v = FE::PrimeField::conditional_select(&w, &tau, choice);
                sum += two.multiply_by_prime_subfield(v);
            }
            sum *= *pow;
            res += sum;
        }
        self.counter += 1;
        Ok(res)
    }
}
