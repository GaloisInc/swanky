// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector Oblivious Linear-function Evaluation (SVOLE)
//!
//! This module provides implementations of SVOLE Traits.



#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{CopeeReceiver, CopeeSender, Fp, Fpr, Params, SVoleReceiver, SVoleSender},
};
use ff::*;
//#[cfg(feature = "derive")]
//pub use ff_derive::*;
use crate::svole::copee::*;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Malicious};
use std::marker::PhantomData;

//use scuttlebutt::ff_derive::Fp as PrimeField;
/// A SVOLE Sender.
#[derive(Debug)]
pub struct Sender<OT: OtSender + Malicious, CP: CopeeSender> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
}

/// A SVOLE Receiver.
#[derive(Debug)]
struct Receiver<OT: OtReceiver + Malicious, CP: CopeeReceiver> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
}

impl<OT: OtSender<Msg = Block> + Malicious, CP: CopeeSender> SVoleSender for Sender<OT, CP> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let _csender = CP::init(channel)?;
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
        })
    }

    fn send<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<(Vec<Fpr>, Vec<Fpr>), Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut u: Vec<Fp> = Vec::new();
        for _i in 0..Params::N {
            u.push(rng.gen::<Fp>())
        }
        let _u = u.clone();
        let mut a: Vec<Fp> = Vec::new();
        for _i in 0..Params::POWR {
            a.push(rng.gen::<Fp>());
        }
        let _a = a.clone();
        let mut sender = CP::init(channel)?;
        let wv = sender.send(channel, u)?;
        let mut _wv = wv.clone();
        /// Calling COPEe on the vector a
        let cv = sender.send(channel, a)?;
        let mut _cv = cv;
        /// Step3. Sender receives chi vector from the receiver
        let mut chiv: Vec<Fp> = (0..Params::N).map(|_| channel.read_fp().unwrap()).collect();
        let mut _chiv = chiv.clone();
        /// Sender computes x
        let temp1: Fp = (0..Params::N).fold(Field::zero(), |sum, i| {
            _chiv[i].mul_assign(&_u[i]);
            chiv[i].add_assign(&sum);
            chiv[i]
        });
        let x: Fp = (0..Params::POWR).fold(temp1, |mut sum, i| {
            sum.add_assign(&_a[i]);
            sum
        });
        /// Sender computes z
        let temp2: Fp = (0..Params::N).fold(Field::zero(), |mut sum, i| {
            _chiv[i].mul_assign(&_wv[i]);
            sum.add_assign(&_chiv[i]);
            sum
        });
        let z: Fp = (0..Params::POWR).fold(temp2, |mut sum, i| {
            _cv[i].mul_assign(&g_gen().pow([i as u64 - 1]));
            sum.add_assign(&_cv[i]);
            sum
        });
        channel.write_fp(x)?;
        channel.write_fp(z)?;
        Ok((_u, wv))
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious, CP: CopeeReceiver> SVoleReceiver
    for Receiver<OT, CP>
{
    type Msg = Block;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
        })
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Fpr>> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut chiv: Vec<Fpr> = (0..Params::N).map(|_| rng.gen::<Fpr>()).collect();
        let (mut cp_receiver, delta) = CP::init(channel).unwrap();
        let v: Vec<Fp> = cp_receiver.receive(channel, Params::N).unwrap();
        let mut b: Vec<Fp> = cp_receiver.receive(channel, Params::POWR).unwrap();
        let mut x: Fp = channel.read_fp().unwrap();
        let z: Fp = channel.read_fp().unwrap();
        /// compute y
        let mut y: Fp = (0..Params::N).fold(Field::zero(), |sum, i| {
            chiv[i].mul_assign(&v[i]);
            chiv[i].add_assign(&sum);
            chiv[i]
        });
        let temp: Fp = (0..Params::POWR).fold(Field::zero(), |sum, i| {
            b[i].mul_assign(&g_gen().pow([i as u64 - 1]));
            b[i].add_assign(&sum);
            b[i]
        });
        y.add_assign(&temp);
        x.mul_assign(&delta);
        y.add_assign(&x);
        if z == y {
            Some(v)
        } else {
            None
        }
    }
}
