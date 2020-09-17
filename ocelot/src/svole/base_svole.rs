// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang base SVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 13).

use crate::{
    errors::Error,
    svole::{
        svole_utils::{dot_prod, to_fpr},
        CopeeReceiver,
        CopeeSender,
        SVoleReceiver,
        SVoleSender,
    },
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
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
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
        let mut w = vec![FE::zero(); len];
        for i in 0..len {
            w[i] = self.copee.send(channel, &u[i])?;
        }
        let mut c = vec![FE::zero(); r];
        for i in 0..r {
            c[i] = self.copee.send(channel, &a[i])?;
        }
        channel.flush()?;
        let mut chi: Vec<FE> = vec![FE::zero(); len];
        for i in 0..len {
            chi[i] = channel.read_fe()?;
        }
        let u_prime: Vec<FE> = u.iter().map(|x| to_fpr(*x)).collect();
        let mut x = dot_prod(&chi, &u_prime);
        let a_prime: Vec<FE> = a.iter().map(|x| to_fpr(*x)).collect();
        x += dot_prod(&a_prime, &self.pows);
        let mut z: FE = dot_prod(&chi, &w);
        z += dot_prod(&c, &self.pows);
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
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
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
        let mut v: Vec<FE> = vec![FE::zero(); len];
        for i in 0..len {
            v[i] = self.copee.receive(channel)?;
        }
        let mut b: Vec<FE> = vec![FE::zero(); r];
        for i in 0..r {
            b[i] = self.copee.receive(channel)?;
        }
        let chi: Vec<FE> = (0..len).map(|_| FE::random(&mut rng)).collect();
        for x in chi.iter() {
            channel.write_fe(*x)?;
        }
        channel.flush()?;
        let x = channel.read_fe()?;
        let z: FE = channel.read_fe()?;
        let mut y = dot_prod(&chi, &v);
        y += dot_prod(&b, &self.pows);
        let mut delta_ = self.copee.delta().clone();
        delta_ *= x;
        delta_ += y;
        if z == delta_ {
            Ok(v)
        } else {
            return Err(Error::Other(
                "Correlation check fails in base vole protocol, i.e, w != u'Δ + v".to_string(),
            ));
        }
    }
}
