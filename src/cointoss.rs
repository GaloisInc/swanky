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

use crate::errors::Error;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block};
use std::io::{Read, Write};

#[inline]
pub fn send<R: Read, W: Write>(
    mut reader: &mut R,
    mut writer: &mut W,
    seeds: &[Block],
) -> Result<Vec<Block>, Error> {
    let mut out = Vec::with_capacity(seeds.len());
    for seed in seeds.iter() {
        let mut rng = AesRng::from_seed(*seed);
        let mut com = Block::zero();
        rng.fill_bytes(&mut com.as_mut());
        com.write(writer)?;
    }
    writer.flush()?;
    for seed in seeds.iter() {
        let seed_ = Block::read(&mut reader)?;
        out.push(*seed ^ seed_);
    }
    for seed in seeds.iter() {
        seed.write(&mut writer)?;
    }
    writer.flush()?;
    Ok(out)
}

#[inline]
pub fn receive<R: Read, W: Write>(
    mut reader: &mut R,
    mut writer: &mut W,
    seeds: &[Block],
) -> Result<Vec<Block>, Error> {
    let mut coms = Vec::with_capacity(seeds.len());
    let mut out = Vec::with_capacity(seeds.len());
    for _ in 0..seeds.len() {
        let com = Block::read(&mut reader)?;
        coms.push(com);
    }
    for seed in seeds.iter() {
        seed.write(&mut writer)?;
    }
    writer.flush()?;
    for (seed, com) in seeds.iter().zip(coms.into_iter()) {
        let seed_ = Block::read(&mut reader)?;
        let mut rng_ = AesRng::from_seed(seed_);
        let mut check = Block::zero();
        rng_.fill_bytes(&mut check.as_mut());
        if check != com {
            return Err(Error::CommitmentCheck);
        }
        out.push(*seed ^ seed_)
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    #[test]
    fn test() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let seed = rand::random::<Block>();
        let seed_ = rand::random::<Block>();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let output = send(&mut reader, &mut writer, &[seed]).unwrap();
            assert_eq!(output[0], seed ^ seed_);
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let output_ = receive(&mut reader, &mut writer, &[seed_]).unwrap();
        assert_eq!(output_[0], seed ^ seed_);
        handle.join().unwrap();
    }
}
