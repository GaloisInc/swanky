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
use std::os::unix::net::UnixStream;

pub trait CloneStream: Sized {
    fn try_clone(&self) -> Result<Self, Error>;
}

impl CloneStream for UnixStream {
    fn try_clone(&self) -> Result<UnixStream, Error> {
        self.try_clone().map_err(Error::from)
    }
}

pub struct Stream<T: Read + Write + Send> {
    stream: T,
}

impl<T: Read + Write + Send> Stream<T> {
    pub fn new(stream: T) -> Self {
        Self { stream }
    }
    #[inline(always)]
    fn stream(&mut self) -> &mut T {
        &mut self.stream
    }
    #[inline(always)]
    pub fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream()
            .write(pt.compress().as_bytes())
            .map_err(Error::from)
    }
    #[inline(always)]
    pub fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
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
    pub fn write_bool(&mut self, b: bool) -> Result<usize, Error> {
        self.stream().write(&[b as u8]).map_err(Error::from)
    }
    #[inline(always)]
    pub fn read_bool(&mut self) -> Result<bool, Error> {
        let mut data = [0; 1];
        self.stream().read_exact(&mut data)?;
        Ok(data[0] != 0)
    }
    #[inline(always)]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.stream().write(bytes).map_err(Error::from)
    }
    #[inline(always)]
    pub fn read_bytes(&mut self, nbytes: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0; nbytes];
        self.stream().read_exact(&mut v)?;
        Ok(v)
    }
    #[inline(always)]
    pub fn read_bytes_inplace(&mut self, mut bytes: &mut [u8]) -> Result<(), Error> {
        self.stream().read_exact(&mut bytes)?;
        Ok(())
    }
    #[inline(always)]
    pub fn write_block(&mut self, block: &Block) -> Result<usize, Error> {
        self.stream().write(block).map_err(Error::from)
    }
    #[inline(always)]
    pub fn read_block(&mut self) -> Result<Block, Error> {
        let mut v = [0u8; 16];
        self.stream().read_exact(&mut v)?;
        Ok(v)
    }
}
