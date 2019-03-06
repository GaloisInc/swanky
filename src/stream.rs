// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::io::{Read, Write};

#[inline(always)]
pub fn write_pt<T: Write>(stream: &mut T, pt: &RistrettoPoint) -> Result<usize, Error> {
    stream.write(pt.compress().as_bytes()).map_err(Error::from)
}

#[inline(always)]
pub fn read_pt<T: Read>(stream: &mut T) -> Result<RistrettoPoint, Error> {
    let mut data = [0u8; 32];
    stream.read_exact(&mut data)?;
    let pt = match CompressedRistretto::from_slice(&data).decompress() {
        Some(pt) => pt,
        None => {
            return Err(Error::DecompressPoint);
        }
    };
    Ok(pt)
}

#[inline(always)]
pub fn write_bool<T: Write>(stream: &mut T, b: bool) -> Result<usize, Error> {
    stream.write(&[b as u8]).map_err(Error::from)
}

#[inline(always)]
pub fn read_bool<T: Read>(stream: &mut T) -> Result<bool, Error> {
    let mut data = [0u8; 1];
    stream.read_exact(&mut data)?;
    Ok(data[0] != 0)
}

#[inline(always)]
pub fn write_bytes<T: Write>(stream: &mut T, bytes: &[u8]) -> Result<usize, Error> {
    stream.write(bytes).map_err(Error::from)
}

#[inline(always)]
pub fn read_bytes_inplace<T: Read>(stream: &mut T, mut bytes: &mut [u8]) -> Result<(), Error> {
    stream.read_exact(&mut bytes)?;
    Ok(())
}
