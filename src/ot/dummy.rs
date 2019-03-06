// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of an **entirely insecure** oblivious transfer protocol for
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

pub struct DummyVecOTSender {}
pub struct DummyVecOTReceiver {}

impl ObliviousTransferSender for DummyVecOTSender {
    type Msg = Vec<u8>;

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
        writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = stream::read_bool(&mut reader)?;
            bs.push(b);
        }
        let mut j = 0;
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            j = j + 1;
            let m = if b { &m.1 } else { &m.0 };
            let l = unsafe { std::mem::transmute::<usize, [u8; 8]>(m.len()) };
            writer.write(&l)?;
            writer.write(&m)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl ObliviousTransferReceiver for DummyVecOTReceiver {
    type Msg = Vec<u8>;

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
    ) -> Result<Vec<Self::Msg>, Error> {
        for b in inputs.iter() {
            stream::write_bool(writer, *b)?;
        }
        writer.flush()?;
        let mut out = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let mut data = [0u8; 8];
            reader.read_exact(&mut data)?;
            let l = unsafe { std::mem::transmute::<[u8; 8], usize>(data) };
            let mut data = vec![0u8; l];
            reader.read_exact(&mut data)?;
            out.push(data);
        }
        Ok(out)
    }
}
