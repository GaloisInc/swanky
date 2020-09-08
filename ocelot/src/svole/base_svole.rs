// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang base SVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 13).

use crate::{
    errors::Error,
    svole::{copee::to_fpr, CopeeReceiver, CopeeSender, SVoleReceiver, SVoleSender},
};
use generic_array::typenum::Unsigned;
use rand::CryptoRng;
use rand_core::RngCore;
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// sVOLE sender.
#[derive(Clone)]
pub struct Sender<CP: CopeeSender> {
    copee: CP,
}

/// sVOLE receiver.
#[derive(Clone)]
pub struct Receiver<CP: CopeeReceiver> {
    copee: CP,
}

impl<FE: FF, CP: CopeeSender<Msg = FE>> SVoleSender for Sender<CP> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let copee = CP::init(channel, rng)?;
        Ok(Self { copee })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let g = FE::generator();
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
        let x = chi.iter().zip(u.iter()).fold(FE::zero(), |sum, (chi, u)| {
            let mut chi_ = chi.clone();
            chi_.mul_assign(to_fpr(*u));
            chi_.add_assign(sum);
            chi_
        });
        let x = (0..r).fold(x, |mut sum, h| {
            let mut g_h = g.pow(h as u128);
            g_h.mul_assign(to_fpr(a[h]));
            sum.add_assign(g_h);
            sum
        });
        let z: FE = chi
            .iter()
            .cloned()
            .zip(w.iter().cloned())
            .map(|(chi, w)| chi * w)
            .sum();

        let z = (0..r).fold(z, |mut sum, h| {
            let mut g_h = g.pow(h as u128);
            g_h.mul_assign(c[h]);
            sum.add_assign(g_h);
            sum
        });
        channel.write_fe(x)?;
        channel.write_fe(z)?;
        channel.flush()?;
        let res = u.iter().zip(w.iter()).map(|(u, w)| (*u, *w)).collect();
        Ok(res)
    }
}

impl<FE: FF, CP: CopeeReceiver<Msg = FE>> SVoleReceiver for Receiver<CP> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let cp = CP::init(channel, rng)?;
        Ok(Self { copee: cp })
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
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let v: Vec<FE> = (0..len)
            .map(|_| self.copee.receive(channel).unwrap())
            .collect();
        let b: Vec<FE> = (0..r)
            .map(|_| self.copee.receive(channel).unwrap())
            .collect();
        let chi: Vec<FE> = (0..len).map(|_| FE::random(&mut rng)).collect();
        for x in chi.iter() {
            channel.write_fe(*x)?;
        }
        channel.flush()?;
        let x = channel.read_fe()?;
        let z: FE = channel.read_fe()?;
        let y = (0..len).fold(FE::zero(), |sum, i| {
            let mut chi_ = chi[i].clone();
            chi_.mul_assign(v[i]);
            chi_.add_assign(sum);
            chi_
        });
        let y = (0..r).fold(y, |sum, h| {
            let mut powr = g.pow(h as u128);
            powr.mul_assign(b[h]);
            powr.add_assign(sum);
            powr
        });
        let mut delta_ = self.copee.delta().clone();
        delta_.mul_assign(x);
        delta_.add_assign(y);
        if z == delta_ {
            Ok(v)
        } else {
            return Err(Error::Other(
                "The sender is cheating. Hence, aborting the protocol".to_string(),
            ));
        }
    }
}
