// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{AbstractChannel, Channel};
use std::io::{Read, Result, Write};

/// An object for tracking the number of bits read from a stream.
struct TrackReader<R: Read> {
    inner: R,
    nbits: usize,
}

impl<R: Read> TrackReader<R> {
    /// Make a new `TrackReader` from an inner `Read` object.
    pub fn new(inner: R) -> Self {
        Self { inner, nbits: 0 }
    }
    /// Clear the count of bits read.
    pub fn clear(&mut self) {
        self.nbits = 0;
    }
    /// Return the count of bits read.
    pub fn count(&self) -> usize {
        self.nbits
    }
    /// Return the count in kilobits.
    pub fn kilobits(&self) -> f64 {
        self.count() as f64 / 1000.0
    }
}

impl<R: Read> Read for TrackReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.nbits += buf.len() * 8;
        self.inner.read(buf)
    }
}

/// An object for tracking the number of bits written to a stream.
struct TrackWriter<W: Write> {
    inner: W,
    nbits: usize,
}

impl<W: Write> TrackWriter<W> {
    /// Make a new `TrackWriter` from an inner `Write` object.
    pub fn new(inner: W) -> Self {
        Self { inner, nbits: 0 }
    }
    /// Clear the count of bits written.
    pub fn clear(&mut self) {
        self.nbits = 0;
    }
    /// Return the count of bits written.
    pub fn count(&self) -> usize {
        self.nbits
    }
    /// Return the count in kilobits.
    pub fn kilobits(&self) -> f64 {
        self.count() as f64 / 1000.0
    }
}

impl<W: Write> Write for TrackWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.nbits += buf.len() * 8;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// A channel for tracking the number of bits read/written.
pub struct TrackChannel<R: Read, W: Write> {
    channel: Channel<TrackReader<R>, TrackWriter<W>>,
}

impl<R: Read, W: Write> TrackChannel<R, W> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let channel = Channel::new(TrackReader::new(reader), TrackWriter::new(writer));
        Self { channel }
    }

    /// Clear the number of bits read/written.
    pub fn clear(&self) {
        self.channel.reader.borrow_mut().clear();
        self.channel.writer.borrow_mut().clear();
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.channel.writer.borrow().kilobits()
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.channel.reader.borrow().kilobits()
    }
}

impl<R: Read, W: Write> AbstractChannel for TrackChannel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.channel.write_bytes(bytes)
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.channel.read_bytes(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.channel.flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
        }
    }
}
