// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::comm::{TrackReader, TrackWriter};
use crate::{Block, Block512};
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::cell::RefCell;
use std::io::{Read, Result, Write};
use std::rc::Rc;

/// A trait for managing I/O. `AbstractChannel`s are clonable, and provide basic
/// read/write capabilities for both common and scuttlebutt-specific types.
pub trait AbstractChannel {
    /// Read a slice of `u8`s from the channel.
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
    /// Write a slice of `u8`s to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;
    /// Flush the channel.
    fn flush(&mut self) -> Result<()>;
    /// Clone the channel.
    fn clone(&self) -> Self
    where
        Self: Sized;

    /// Write a `bool` to the channel.
    #[inline(always)]
    fn write_bool(&mut self, b: bool) -> Result<()> {
        self.write_bytes(&[b as u8])?;
        Ok(())
    }

    /// Read a `bool` from the channel.
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool> {
        let mut data = [0u8; 1];
        self.read_bytes(&mut data)?;
        Ok(data[0] != 0)
    }

    /// Write a `usize` to the channel.
    #[inline(always)]
    fn write_usize(&mut self, s: usize) -> Result<()> {
        let data: [u8; 8] = unsafe { std::mem::transmute(s) };
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read a `usize` from the channel.
    #[inline(always)]
    fn read_usize(&mut self) -> Result<usize> {
        let mut data = [0u8; 8];
        self.read_bytes(&mut data)?;
        let s = unsafe { std::mem::transmute(data) };
        Ok(s)
    }

    /// Write a `Block` to the channel.
    #[inline(always)]
    fn write_block(&mut self, b: &Block) -> Result<()> {
        self.write_bytes(b.as_ref())?;
        Ok(())
    }

    /// Read a `Block` from the channel.
    #[inline(always)]
    fn read_block(&mut self) -> Result<Block> {
        let mut v = Block::default();
        self.read_bytes(v.as_mut())?;
        Ok(v)
    }

    /// Write a `Block512` to the channel.
    #[inline(always)]
    fn write_block512(&mut self, b: &Block512) -> Result<()> {
        for block in b.0.iter() {
            self.write_block(block)?;
        }
        Ok(())
    }

    /// Read a `Block512` from the channel.
    #[inline(always)]
    fn read_block512(&mut self) -> Result<Block512> {
        let mut data = [0u8; 64];
        self.read_bytes(&mut data)?;
        Ok(Block512::from(data))
    }

    /// Write a `RistrettoPoint` to the channel.
    #[cfg(feature = "curve25519-dalek")]
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<()> {
        self.write_bytes(pt.compress().as_bytes())?;
        Ok(())
    }

    /// Read a `RistrettoPoint` from the channel.
    #[cfg(feature = "curve25519-dalek")]
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint> {
        let mut data = [0u8; 32];
        self.read_bytes(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unable to decompress ristretto point",
                ));
            }
        };
        Ok(pt)
    }
}

/// A standard read/write channel.
pub struct Channel<R, W> {
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

impl<R: Read, W: Write> Channel<R, W> {
    /// Make a new `Channel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Rc::new(RefCell::new(reader));
        let writer = Rc::new(RefCell::new(writer));
        Self { reader, writer }
    }

    /// Return a reader object wrapped in `Rc<RefCell>`.
    pub fn reader(&mut self) -> Rc<RefCell<R>> {
        self.reader.clone()
    }

    /// Return a writer object wrapped in `Rc<RefCell>`.
    pub fn writer(&mut self) -> Rc<RefCell<W>> {
        self.writer.clone()
    }
}

impl<R: Read, W: Write> AbstractChannel for Channel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.borrow_mut().write(bytes)?;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.borrow_mut().read_exact(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.writer.borrow_mut().flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
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
    pub fn write_kilobits(&self) -> f64 {
        self.channel.writer.borrow().kilobits()
    }

    /// Return the number of kilobits read from the channel.
    pub fn read_kilobits(&self) -> f64 {
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
