// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::stream;
use crate::{Block, ObliviousTransfer};
use failure::Error;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Implementation if an **entirely insecure** oblivious transfer protocol for
/// testing purposes.
pub struct DummyOT<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<R: Read, W: Write> ObliviousTransfer<R, W> for DummyOT<R, W> {
    type Msg = Block;

    fn new() -> Self {
        Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
        }
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

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    #[test]
    fn test() {
        let m0 = rand::random::<Block>();
        let m1 = rand::random::<Block>();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut ot = DummyOT::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            ot.send(&mut reader, &mut writer, &[(m0, m1)]).unwrap();
        });
        let mut ot = DummyOT::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let result = ot.receive(&mut reader, &mut writer, &[b]).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
