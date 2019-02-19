// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Naor-Pinkas oblivious transfer protocol.
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library.

use crate::stream;
use crate::{ObliviousTransferReceiver, ObliviousTransferSender, SemiHonest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use scuttlebutt::{AesRng, Block};
use std::io::{Read, Write};
use std::marker::PhantomData;

pub struct NaorPinkasOTSender<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    rng: AesRng,
}

pub struct NaorPinkasOTReceiver<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    rng: AesRng,
}

impl<R: Read + Send, W: Write + Send> ObliviousTransferSender<R, W> for NaorPinkasOTSender<R, W> {
    type Msg = Block;

    fn init(_: &mut R, _: &mut W) -> Result<Self, Error> {
        let rng = AesRng::new();
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            rng,
        })
    }

    fn send(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut pks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = RistrettoPoint::random(&mut self.rng);
            stream::write_pt(writer, &c)?;
            cs.push(c);
        }
        writer.flush()?;
        for c in cs.into_iter() {
            let pk0 = stream::read_pt(reader)?;
            pks.push((pk0, c - pk0));
        }
        for (i, (input, pk)) in inputs.iter().zip(pks.into_iter()).enumerate() {
            let r0 = Scalar::random(&mut self.rng);
            let r1 = Scalar::random(&mut self.rng);
            let e00 = &r0 * &RISTRETTO_BASEPOINT_TABLE;
            let e10 = &r1 * &RISTRETTO_BASEPOINT_TABLE;
            let h = Block::hash_pt(i, &(pk.0 * r0));
            let e01 = h ^ input.0;
            let h = Block::hash_pt(i, &(pk.1 * r1));
            let e11 = h ^ input.1;
            stream::write_pt(writer, &e00)?;
            e01.write(writer)?;
            stream::write_pt(writer, &e10)?;
            e11.write(writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl<R: Read + Send, W: Write + Send> ObliviousTransferReceiver<R, W>
    for NaorPinkasOTReceiver<R, W>
{
    type Msg = Block;

    fn init(_: &mut R, _: &mut W) -> Result<Self, Error> {
        let rng = AesRng::new();
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            rng,
        })
    }

    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut ks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = stream::read_pt(reader)?;
            cs.push(c);
        }
        for (b, c) in inputs.iter().zip(cs.into_iter()) {
            let k = Scalar::random(&mut self.rng);
            let pkσ = &k * &RISTRETTO_BASEPOINT_TABLE;
            let pkσ_ = c - pkσ;
            match b {
                false => stream::write_pt(writer, &pkσ)?,
                true => stream::write_pt(writer, &pkσ_)?,
            };
            ks.push(k);
        }
        writer.flush()?;
        inputs
            .iter()
            .zip(ks.into_iter())
            .enumerate()
            .map(|(i, (b, k))| {
                let e00 = stream::read_pt(reader)?;
                let e01 = Block::read(reader)?;
                let e10 = stream::read_pt(reader)?;
                let e11 = Block::read(reader)?;
                let (eσ0, eσ1) = match b {
                    false => (e00, e01),
                    true => (e10, e11),
                };
                let h = Block::hash_pt(i, &(eσ0 * k));
                Ok(h ^ eσ1)
            })
            .collect()
    }
}

impl<R: Read, W: Write> SemiHonest for NaorPinkasOTSender<R, W> {}
impl<R: Read, W: Write> SemiHonest for NaorPinkasOTReceiver<R, W> {}
