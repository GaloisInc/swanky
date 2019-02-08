// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Block;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use failure::Error;
use std::io::Error as IOError;
use std::io::{ErrorKind, Read, Write};

#[inline(always)]
pub fn write_pt<T: Read + Write + Send>(
    stream: &mut T,
    pt: &RistrettoPoint,
) -> Result<usize, Error> {
    stream.write(pt.compress().as_bytes()).map_err(Error::from)
}

#[inline(always)]
pub fn read_pt<T: Read + Write + Send>(stream: &mut T) -> Result<RistrettoPoint, Error> {
    let mut data = [0; 32];
    stream.read_exact(&mut data)?;
    let pt = match CompressedRistretto::from_slice(&data).decompress() {
        Some(pt) => pt,
        None => {
            return Err(Error::from(IOError::new(
                ErrorKind::InvalidData,
                "Unable to decompress point",
            )));
        }
    };
    Ok(pt)
}
#[inline(always)]
pub fn write_bool<T: Read + Write + Send>(stream: &mut T, b: bool) -> Result<usize, Error> {
    stream.write(&[b as u8]).map_err(Error::from)
}
#[inline(always)]
pub fn read_bool<T: Read + Write + Send>(stream: &mut T) -> Result<bool, Error> {
    let mut data = [0; 1];
    stream.read_exact(&mut data)?;
    Ok(data[0] != 0)
}
#[inline(always)]
pub fn write_bytes<T: Read + Write + Send>(stream: &mut T, bytes: &[u8]) -> Result<usize, Error> {
    stream.write(bytes).map_err(Error::from)
}
// #[inline(always)]
// pub fn read_bytes<T: Read + Write + Send>(stream: &mut T, nbytes: usize) -> Result<Vec<u8>, Error> {
//     let mut v = vec![0; nbytes];
//     stream.read_exact(&mut v)?;
//     Ok(v)
// }
#[inline(always)]
pub fn read_bytes_inplace<T: Read + Write + Send>(
    stream: &mut T,
    mut bytes: &mut [u8],
) -> Result<(), Error> {
    stream.read_exact(&mut bytes)?;
    Ok(())
}
#[inline(always)]
pub fn write_block<T: Read + Write + Send>(stream: &mut T, block: &Block) -> Result<usize, Error> {
    stream.write(block).map_err(Error::from)
}
#[inline(always)]
pub fn read_block<T: Read + Write + Send>(stream: &mut T) -> Result<Block, Error> {
    let mut v = [0u8; 16];
    stream.read_exact(&mut v)?;
    Ok(v)
}
