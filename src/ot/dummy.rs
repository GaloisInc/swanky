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
use scuttlebutt::Block;
use std::io::{Read, Write};
use std::marker::PhantomData;

pub struct DummyOTSender<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

pub struct DummyOTReceiver<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<R: Read, W: Write> ObliviousTransferSender<R, W> for DummyOTSender<R, W> {
    type Msg = Block;

    fn init(_: &mut R, _: &mut W) -> Result<Self, Error> {
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
        })
    }

    fn send(
        &mut self,
        mut reader: &mut R,
        mut writer: &mut W,
        inputs: &[(Block, Block)],
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

impl<R: Read, W: Write> ObliviousTransferReceiver<R, W> for DummyOTReceiver<R, W> {
    type Msg = Block;

    fn init(_: &mut R, _: &mut W) -> Result<Self, Error> {
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
        })
    }

    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        for b in inputs.iter() {
            stream::write_bool(writer, *b)?;
        }
        writer.flush()?;
        (0..inputs.len()).map(|_| Block::read(reader)).collect()
    }
}
