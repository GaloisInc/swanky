// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{AbstractChannel, Channel};
use std::{
    io::{Read, Result, Write},
    sync::{Arc, Mutex},
};

use super::GetBlockByIndex;

/// A channel for tracking the number of bits read/written.
pub struct TrackChannel<R: GetBlockByIndex, W>(Arc<Mutex<InternalTrackChannel<R, W>>>);

struct InternalTrackChannel<R: GetBlockByIndex, W> {
    channel: Channel<R, W>,
    nbits_read: usize,
    nbits_written: usize,
}

impl<R: Read + GetBlockByIndex, W: Write> TrackChannel<R, W> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let channel = Channel::new(reader, writer);
        let internal = InternalTrackChannel {
            channel,
            nbits_read: 0,
            nbits_written: 0,
        };
        Self(Arc::new(Mutex::new(internal)))
    }

    /// Clear the number of bits read/written.
    pub fn clear(&mut self) {
        let mut int = self.0.lock().unwrap();
        int.nbits_read = 0;
        int.nbits_written = 0;
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.0.lock().unwrap().nbits_written as f64 / 1000.0
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.0.lock().unwrap().nbits_read as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel.
    pub fn total_kilobits(&self) -> f64 {
        let int = self.0.lock().unwrap();
        (int.nbits_written + int.nbits_read) as f64 / 1000.0
    }

    /// Return the number of kilobytes written to the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.0.lock().unwrap().nbits_written as f64 / 8192.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.0.lock().unwrap().nbits_read as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel as kilobytes.
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_written() + self.kilobytes_read()
    }
}

impl<R: Read + GetBlockByIndex, W: Write> AbstractChannel for TrackChannel<R, W> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut int = self.0.lock().unwrap();
        int.nbits_written += bytes.len() * 8;
        int.channel.write_bytes(bytes)?;
        // int.channel.flush()?;
        Ok(())
    }

    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        let mut int = self.0.lock().unwrap();
        int.nbits_read += bytes.len() * 8;
        int.channel.read_bytes(&mut bytes)
    }

    // fn flush(&mut self) -> Result<()> {
    //     self.0.lock().unwrap().channel.flush()
    // }

    // fn clone(&self) -> Self {
    //     Self(self.0.clone())
    // }
}
