// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::rand_aes::AesRng;
use crate::{block, stream, Block};
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
    let mut com = block::zero_block();
    rng.fill_bytes(&mut com);
    stream::write_block(writer, &com)?;
    writer.flush()?;
    let com_ = stream::read_block(&mut reader)?;
    let seed_ = stream::read_block(&mut reader)?;
    stream::write_block(&mut writer, &seed)?;
    writer.flush()?;
    let mut rng_ = AesRng::from_seed(seed_);
    let mut check = block::zero_block();
    rng_.fill_bytes(&mut check);
    if check != com_ {
        return Err(Error::from(std::io::Error::new(
            ErrorKind::InvalidData,
            "Commitment check failed",
        )));
    }
    Ok(block::xor_block(&seed, &seed_))
}

pub fn receive<S>(
    mut reader: &mut BufReader<S>,
    mut writer: &mut BufWriter<S>,
    seed: Block,
) -> Result<Block, Error>
where
    S: Read + Write + Send + Sync,
{
    let mut rng = AesRng::from_seed(seed);
    let mut com = block::zero_block();
    rng.fill_bytes(&mut com);
    let com_ = stream::read_block(&mut reader)?;
    stream::write_block(writer, &com)?;
    stream::write_block(&mut writer, &seed)?;
    writer.flush()?;
    let seed_ = stream::read_block(&mut reader)?;
    let mut rng_ = AesRng::from_seed(seed_);
    let mut check = block::zero_block();
    rng_.fill_bytes(&mut check);
    if check != com_ {
        return Err(Error::from(std::io::Error::new(
            ErrorKind::InvalidData,
            "Commitment check failed",
        )));
    }
    Ok(block::xor_block(&seed, &seed_))
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
            assert_eq!(output, block::xor_block(&seed, &seed_));
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let output_ = receive(&mut reader, &mut writer, seed_).unwrap();
        assert_eq!(output_, block::xor_block(&seed, &seed_));
        handle.join().unwrap();
    }
}
