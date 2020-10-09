// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::AbstractChannel;
use std::{
    net::TcpStream,
    io::{Read, Write, Result},
};

pub struct TcpChannel<TcpStream>{
    stream: TcpStream,
    nbits_read: usize,
    nbits_written: usize,
}

impl TcpChannel<TcpStream> {
    pub fn new(stream: TcpStream) -> Self {
        Self{stream, nbits_read: 0, nbits_written: 0}
    }
}

impl AbstractChannel for TcpChannel<TcpStream>{
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.nbits_written = self.stream.write(bytes)?*8;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.nbits_written = bytes.len()*8;
        self.stream.read_exact(&mut bytes)?;
        Ok(())
    }
    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.try_clone().unwrap(),
            nbits_read: self.nbits_read,
            nbits_written: self.nbits_written,
        }
    }
}
