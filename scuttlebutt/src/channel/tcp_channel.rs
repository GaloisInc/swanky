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
    /// Clear the number of bits read/written.
    pub fn clear(&mut self) {
        self.nbits_read = 0;
        self.nbits_written = 0;
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.nbits_written as f64 / 1000.0
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.nbits_read as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel.
    pub fn total_kilobits(&self) -> f64 {
        (self.nbits_written + self.nbits_read) as f64 / 1000.0
    }

    /// Return the number of kilobytes written to the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.nbits_written as f64 / 8192.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.nbits_read as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel as kilobytes.
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_written() + self.kilobytes_read()
    }
}

impl AbstractChannel for TcpChannel<TcpStream>{
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.nbits_written += self.stream.write(bytes)?*8;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.nbits_written += bytes.len()*8;
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
