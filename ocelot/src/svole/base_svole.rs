// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang base SVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 13).

use crate::{
    errors::Error,
    svole::{utils::to_fpr, CopeeReceiver, CopeeSender, SVoleReceiver, SVoleSender},
};
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// sVOLE sender.
#[derive(Clone)]
pub struct Sender<CP: CopeeSender, FE: FF> {
    copee: CP,
    pows: Vec<FE>,
}

/// sVOLE receiver.
#[derive(Clone)]
pub struct Receiver<CP: CopeeReceiver, FE: FF> {
    copee: CP,
    pows: Vec<FE>,
}

impl<FE: FF, CP: CopeeSender<Msg = FE>> SVoleSender for Sender<CP, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        let copee = CP::init(channel, rng)?;
        Ok(Self { copee, pows })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let u: Vec<FE::PrimeField> = (0..len).map(|_| FE::PrimeField::random(&mut rng)).collect();
        let a: Vec<FE::PrimeField> = (0..r).map(|_| FE::PrimeField::random(&mut rng)).collect();
        let mut w = vec![FE::ZERO; len];
        for i in 0..len {
            w[i] = self.copee.send(channel, &u[i])?;
        }
        let mut z: FE = FE::ZERO;
        for (i, x) in a.iter().enumerate().take(r) {
            let c = self.copee.send(channel, x)?;
            z += c * self.pows[i];
        }
        channel.flush()?;
        let mut x: FE = FE::ZERO;
        for i in 0..len {
            let chi = channel.read_fe::<FE>()?;
            z += chi * w[i];
            x += chi * (to_fpr(u[i]));
        }
        x += a
            .iter()
            .zip(self.pows.iter())
            .map(|(&a, &pow)| to_fpr::<FE>(a) * pow)
            .sum();
        channel.write_fe(x)?;
        channel.write_fe(z)?;
        let res = u.iter().zip(w.iter()).map(|(u, w)| (*u, *w)).collect();
        Ok(res)
    }
}

impl<FE: FF, CP: CopeeReceiver<Msg = FE>> SVoleReceiver for Receiver<CP, FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        let cp = CP::init(channel, rng)?;
        Ok(Self { copee: cp, pows })
    }

    fn delta(&self) -> FE {
        self.copee.delta()
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut v: Vec<FE> = vec![FE::ZERO; len];
        let chi: Vec<FE> = (0..len).map(|_| FE::random(&mut rng)).collect();
        let mut y: FE = FE::ZERO;
        for i in 0..len {
            v[i] = self.copee.receive(channel)?;
            y += chi[i] * v[i];
        }
        for i in 0..r {
            let b = self.copee.receive(channel)?;
            y += self.pows[i] * b
        }
        for x in chi.iter() {
            channel.write_fe(*x)?;
        }
        channel.flush()?;
        let x = channel.read_fe()?;
        let z: FE = channel.read_fe()?;
        let mut delta = self.copee.delta();
        delta *= x;
        delta += y;
        if z == delta {
            Ok(v)
        } else {
            Err(Error::Other(
                "Correlation check fails in base vole protocol, i.e, w != u'Δ + v".to_string(),
            ))
        }
    }
}
