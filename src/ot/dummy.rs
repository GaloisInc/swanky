// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::stream;
use crate::{Block, BlockObliviousTransfer};
use failure::Error;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Implementation if an **entirely insecure** oblivious transfer protocol for
/// testing purposes.
pub struct DummyOT<S: Read + Write + Send + Sync> {
    _s: PhantomData<S>,
}

impl<S: Read + Write + Send + Sync> BlockObliviousTransfer<S> for DummyOT<S> {
    fn new() -> Self {
        Self {
            _s: PhantomData::<S>,
        }
    }

    fn send(&mut self, stream: &mut S, inputs: &[(Block, Block)]) -> Result<(), Error> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = stream::read_bool(stream)?;
            bs.push(b);
        }
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            let m = if b { &m.1 } else { &m.0 };
            stream::write_block(stream, &m)?;
        }
        Ok(())
    }

    fn receive(&mut self, stream: &mut S, inputs: &[bool]) -> Result<Vec<Block>, Error> {
        for b in inputs.iter() {
            stream::write_bool(stream, *b)?;
        }
        (0..inputs.len())
            .map(|_| stream::read_block(stream))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test() {
        let m0 = rand::random::<Block>();
        let m1 = rand::random::<Block>();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (mut sender, mut receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => panic!("Couldn't create pair of sockets: {:?}", e),
        };
        let handle = std::thread::spawn(move || {
            let mut ot = DummyOT::new();
            ot.send(&mut sender, &[(m0, m1)]).unwrap();
        });
        let mut ot = DummyOT::new();
        let result = ot.receive(&mut receiver, &[b]).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
