// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation if an **entirely insecure** oblivious transfer protocol for
//! testing purposes.

use crate::stream;
use crate::{ObliviousTransferReceiver, ObliviousTransferSender};
use failure::Error;
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::io::{Read, Write};

pub struct DummyOTSender {}
pub struct DummyOTReceiver {}

impl ObliviousTransferSender for DummyOTSender {
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        _: &mut R,
        _: &mut W,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
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
        Ok(())
    }
}

impl ObliviousTransferReceiver for DummyOTReceiver {
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        _: &mut R,
        _: &mut W,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
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
        (0..inputs.len()).map(|_| Block::read(reader)).collect()
    }
}
