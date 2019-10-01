// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{AbstractChannel, Channel};
use std::io::{Read, Result, Write};

/// A channel for tracking the number of bits read/written.
pub struct TrackChannel<R, W> {
    channel: Channel<R, W>,
    nbits_read: usize,
    nbits_written: usize,
}

impl<R: Read, W: Write> TrackChannel<R, W> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let channel = Channel::new(reader, writer);
        Self {
            channel,
            nbits_read: 0,
            nbits_written: 0,
        }
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
        self.kilobits_written() + self.kilobits_read()
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

impl<R: Read, W: Write> AbstractChannel for TrackChannel<R, W> {
    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.nbits_written += bytes.len() * 8;
        self.channel.write_bytes(bytes)
    }

    #[inline]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.nbits_read += bytes.len() * 8;
        self.channel.read_bytes(&mut bytes)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.channel.flush()
    }

    #[inline]
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            nbits_written: self.nbits_written,
            nbits_read: self.nbits_read,
        }
    }
}
