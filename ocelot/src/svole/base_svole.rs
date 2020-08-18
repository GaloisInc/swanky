// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector Oblivious Linear-function Evaluation (SVOLE)
//!
//! This module provides implementations of SVOLE Traits.

//#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{CopeeReceiver, CopeeSender, Params, SVoleReceiver, SVoleSender},
};
use rand::SeedableRng;
use scuttlebutt::{
    field::{FiniteField as FF, Fp},
    AbstractChannel, AesRng, Block, Malicious,
};
use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{AddAssign, MulAssign},
};

//use scuttlebutt::ff_derive::Fp as PrimeField;
/// A SVOLE Sender.
#[derive(Clone)]
pub struct Sender<OT: OtSender + Malicious, CP: CopeeSender> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    copee: CP,
}

/// A SVOLE Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtReceiver + Malicious, CP: CopeeReceiver> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    delta: Fp,
    copee: CP,
}

/// Implement SVoleSender for Sender type.
impl<OT: OtSender<Msg = Block> + Malicious, CP: CopeeSender<Msg = Fp>> SVoleSender
    for Sender<OT, CP>
{
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let csender = CP::init(channel).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            copee: csender,
        })
    }

    fn send<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<(Vec<Fp>, Vec<Fp>), Error> {
        let g:Fp = FF::generator();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        /// Sampling `ui`s i in `[n]`.
        let u: Vec<Fp> = (0..Params::N).map(|_| FF::random(&mut rng)).collect();
        assert_eq!(u.len(), Params::N);
        /// Sampling `ah`s h in `[r]`.
        let a: Vec<Fp> = (0..Params::R).map(|_| FF::random(&mut rng)).collect();
        assert_eq!(a.len(), Params::R);
        /// Calling COPEe extend on the vector `u`.
        let w = self.copee.send(channel, u.clone())?;
        /// Calling COPEe on the vector `a`
        let mut c = self.copee.send(channel, a.clone())?;
        /// Sender receives `chi`s from the receiver
        let mut chi: Vec<Fp> = (0..Params::N)
            .map(|_| {
                let mut data = [0u8; 16];
                channel.read_bytes(&mut data).unwrap();
                Fp::try_from(u128::from_le_bytes(data)).unwrap()
            })
            .collect();
        /// Sender computes x
        let x_sum: Fp = (0..Params::N).fold(FF::zero(), |sum, i| {
            chi[i].mul_assign(&u[i]);
            chi[i].add_assign(&sum);
            chi[i]
        });
        let x: Fp = (0..Params::R).fold(x_sum, |mut sum, h| {
            let mut g_h = g.pow(h as u128);
            g_h.mul_assign(&a[h]);
            sum.add_assign(&g_h);
            sum
        });

        /// Sender computes z
        let z_sum: Fp = (0..Params::N).fold(FF::zero(), |mut sum, i| {
            chi[i].mul_assign(&w[i]);
            sum.add_assign(&chi[i]);
            sum
        });
        let z: Fp = (0..Params::R).fold(z_sum, |mut sum, h| {
            let g_h = g.pow(h as u128);
            c[h].mul_assign(&g_h);
            sum.add_assign(&c[h]);
            sum
        });

        /// Sends out (x, z) to the Receiver.
        channel.write_bytes(x.to_bytes().as_slice())?;
        channel.write_bytes(z.to_bytes().as_slice())?;
        Ok((u, w))
    }
}

/// Implement SVoleReceiver for Receiver type.
impl<OT: OtReceiver<Msg = Block> + Malicious, CP: CopeeReceiver<Msg = Fp>> SVoleReceiver
    for Receiver<OT, CP>
{
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let cp = CP::init(channel).unwrap();
        let delta = cp.get_delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            copee: cp,
            delta,
        })
    }

    fn get_delta(&self) -> Fp {
        self.delta
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Fp>> {
        let v: Vec<Fp> = self.copee.receive(channel, Params::N).unwrap();
        let mut b: Vec<Fp> = self.copee.receive(channel, Params::R).unwrap();
        /// Sampling `chi`s.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut chi: Vec<Fp> = (0..Params::N).map(|_| FF::random(&mut rng)).collect();
        /// Send `chi`s to the Sender.
        for item in &mut chi {
            channel
                .write_bytes(item.to_bytes().as_slice())
                .unwrap();
        }
        /// Receive (x, z) from the Sender.
        let mut data_x = [0u8; 16];
        channel.read_bytes(&mut data_x).unwrap();
        let x = Fp::try_from(u128::from_le_bytes(data_x)).unwrap();
        let mut data_z = [0u8; 16];
        channel.read_bytes(&mut data_z).unwrap();
        let z = Fp::try_from(u128::from_le_bytes(data_z)).unwrap();
        /// compute y
        let y_sum: Fp = (0..Params::N).fold(FF::zero(), |sum, i| {
            chi[i].mul_assign(&v[i]);
            chi[i].add_assign(&sum);
            chi[i]
        });
        let g: Fp = FF::generator();
        let y: Fp = (0..Params::R).fold(y_sum, |sum, h| {
            let powr = g.pow(h as u128);
            b[h].mul_assign(&powr);
            b[h].add_assign(&sum);
            b[h]
        });
        let mut delta_ = self.delta.clone();
        delta_.mul_assign(&x);
        delta_.add_assign(&y);
        if z == delta_ {
            Some(v)
        } else {
            None
        }
    }
}
