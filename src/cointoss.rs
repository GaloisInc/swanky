// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of a simple two-party coin tossing protocol using a PRG as a
//! commitment.
//!
//! On input `seed`, the sender computes `r := PRG(seed)` and sends `r` to the
//! receiver. It then receives `seed_` from the receiver and outputs `seed ⊕
//! seed_`. Likewise, on input `seed`, the receiver gets `r`, sends `seed` to
//! the sender, and then receives `seed_`, checking that `PRG(seed_) = r`.

use crate::rand_aes::AesRng;
use crate::{block, Block};
use failure::Error;
use rand_core::{RngCore, SeedableRng};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};

pub fn send<S>(
    mut reader: &mut BufReader<S>,
    mut writer: &mut BufWriter<S>,
    seed: Block,
) -> Result<Block, Error>
where
    S: Read + Write + Send + Sync,
{
    let mut rng = AesRng::from_seed(seed);
    let mut com = Block::zero();
    rng.fill_bytes(&mut com.as_mut());
    block::write_block(writer, &com)?;
    writer.flush()?;
    let seed_ = block::read_block(&mut reader)?;
    block::write_block(&mut writer, &seed)?;
    writer.flush()?;
    Ok(seed ^ seed_)
}

pub fn receive<S>(
    mut reader: &mut BufReader<S>,
    mut writer: &mut BufWriter<S>,
    seed: Block,
) -> Result<Block, Error>
where
    S: Read + Write + Send + Sync,
{
    let com_ = block::read_block(&mut reader)?;
    block::write_block(&mut writer, &seed)?;
    writer.flush()?;
    let seed_ = block::read_block(&mut reader)?;
    let mut rng_ = AesRng::from_seed(seed_);
    let mut check = Block::zero();
    rng_.fill_bytes(&mut check.as_mut());
    if check != com_ {
        return Err(Error::from(std::io::Error::new(
            ErrorKind::InvalidData,
            "Commitment check failed",
        )));
    }
    Ok(seed ^ seed_)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let seed_ = rand::random::<Block>();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let output = send(&mut reader, &mut writer, seed).unwrap();
            assert_eq!(output, seed ^ seed_);
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let output_ = receive(&mut reader, &mut writer, seed_).unwrap();
        assert_eq!(output_, seed ^ seed_);
        handle.join().unwrap();
    }
}
