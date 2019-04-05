// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! A module for useful communication-related objects.

use std::io::{Read, Result, Write};

/// An object for tracking the number of bits read from a stream.
pub struct TrackReader<R: Read> {
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
pub struct TrackWriter<W: Write> {
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
