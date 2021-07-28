// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Naor-Pinkas oblivious transfer protocol (cf.
//! <https://dl.acm.org/citation.cfm?id=365502>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut pks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = RistrettoPoint::random(&mut rng);
            channel.send(&c)?;
            cs.push(c);
        }
        channel.flush()?;
        for c in cs.into_iter() {
            let pk0: RistrettoPoint = channel.receive()?;
            pks.push((pk0, c - pk0));
        }
        for (i, (input, pk)) in inputs.iter().zip(pks.into_iter()).enumerate() {
            let r0 = Scalar::random(&mut rng);
            let r1 = Scalar::random(&mut rng);
            let e00 = &r0 * &RISTRETTO_BASEPOINT_TABLE;
            let e10 = &r1 * &RISTRETTO_BASEPOINT_TABLE;
            let h = Block::hash_pt(i as u128, &(pk.0 * r0));
            let e01 = h ^ input.0;
            let h = Block::hash_pt(i as u128, &(pk.1 * r1));
            let e11 = h ^ input.1;
            channel.send(&e00)?;
            channel.send(&e01)?;
            channel.send(&e10)?;
            channel.send(&e11)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Sender")
    }
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut ks = Vec::with_capacity(m);
        for _ in 0..m {
            let c: RistrettoPoint = channel.receive()?;
            cs.push(c);
        }
        for (b, c) in inputs.iter().zip(cs.into_iter()) {
            let k = Scalar::random(&mut rng);
            let pk = &k * &RISTRETTO_BASEPOINT_TABLE;
            let pk_ = c - pk;
            match b {
                false => channel.send(&pk)?,
                true => channel.send(&pk_)?,
            };
            ks.push(k);
        }
        channel.flush()?;
        inputs
            .iter()
            .zip(ks.into_iter())
            .enumerate()
            .map(|(i, (b, k))| {
                let e00: RistrettoPoint = channel.receive()?;
                let e01: Block = channel.receive()?;
                let e10: RistrettoPoint = channel.receive()?;
                let e11: Block = channel.receive()?;
                let (e0, e1) = match b {
                    false => (e00, e01),
                    true => (e10, e11),
                };
                let h = Block::hash_pt(i as u128, &(e0 * k));
                Ok(h ^ e1)
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Receiver")
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}
