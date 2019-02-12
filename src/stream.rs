// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use failure::Error;
use std::io::Error as IOError;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};

#[inline(always)]
pub fn write_pt<T: Read + Write + Send>(
    stream: &mut BufWriter<T>,
    pt: &RistrettoPoint,
) -> Result<usize, Error> {
    stream.write(pt.compress().as_bytes()).map_err(Error::from)
}

#[inline(always)]
pub fn read_pt<T: Read + Write + Send>(stream: &mut BufReader<T>) -> Result<RistrettoPoint, Error> {
    let mut data = [0u8; 32];
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
pub fn write_bool<T: Read + Write + Send>(
    stream: &mut BufWriter<T>,
    b: bool,
) -> Result<usize, Error> {
    stream.write(&[b as u8]).map_err(Error::from)
}
#[inline(always)]
pub fn read_bool<T: Read + Write + Send>(stream: &mut BufReader<T>) -> Result<bool, Error> {
    let mut data = [0; 1];
    stream.read_exact(&mut data)?;
    Ok(data[0] != 0)
}
#[inline(always)]
pub fn write_bytes<T: Read + Write + Send>(
    stream: &mut BufWriter<T>,
    bytes: &[u8],
) -> Result<usize, Error> {
    stream.write(bytes).map_err(Error::from)
}
#[inline(always)]
pub fn read_bytes_inplace<T: Read + Write + Send>(
    stream: &mut BufReader<T>,
    mut bytes: &mut [u8],
) -> Result<(), Error> {
    stream.read_exact(&mut bytes)?;
    Ok(())
}
