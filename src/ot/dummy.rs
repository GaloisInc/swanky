// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of an **entirely insecure** oblivious transfer protocol for
//! testing purposes.

use crate::errors::Error;
use crate::ot::{Receiver as OtReceiver, Sender as OtSender};
use crate::stream;
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::io::{Read, Write};

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        _: &mut R,
        _: &mut W,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        mut reader: &mut R,
        mut writer: &mut W,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = stream::read_bool(&mut reader)?;
            bs.push(b);
        }
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            let m = if b { m.1 } else { m.0 };
            m.write(&mut writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Dummy Sender")
    }
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        _: &mut R,
        _: &mut W,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        for b in inputs.iter() {
            stream::write_bool(writer, *b)?;
        }
        writer.flush()?;
        let mut out = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let m = Block::read(reader)?;
            out.push(m);
        }
        Ok(out)
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Dummy Receiver")
    }
}
