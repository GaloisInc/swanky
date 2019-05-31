// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

// use crate::comm::{TrackReader, TrackWriter};
use crate::{Block, Block512};
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::cell::RefCell;
use std::io::{Read, Result, Write};
use std::rc::Rc;

#[derive(Clone)]
pub struct Channel<R, W> {
    pub reader: Rc<RefCell<R>>,
    pub writer: Rc<RefCell<W>>,
}

impl<R: Read, W: Write> Channel<R, W> {
    /// Make a new `Channel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Rc::new(RefCell::new(reader));
        let writer = Rc::new(RefCell::new(writer));
        Self { reader, writer }
    }

    /// Write a `usize` to the channel.
    #[inline(always)]
    pub fn write_usize(&mut self, s: usize) -> Result<()> {
        let data: [u8; 8] = unsafe { std::mem::transmute(s) };
        self.writer.borrow_mut().write_all(&data)?;
        Ok(())
    }

    /// Read a `usize` from the channel.
    #[inline(always)]
    pub fn read_usize(&mut self) -> Result<usize> {
        let mut data = [0u8; 8];
        self.reader.borrow_mut().read_exact(&mut data)?;
        let s = unsafe { std::mem::transmute(data) };
        Ok(s)
    }

    /// Write a `bool` to the channel.
    #[inline(always)]
    pub fn write_bool(&mut self, b: bool) -> Result<usize> {
        self.writer.borrow_mut().write(&[b as u8])
    }

    /// Read a `bool` from the channel.
    #[inline(always)]
    pub fn read_bool(&mut self) -> Result<bool> {
        let mut data = [0u8; 1];
        self.reader.borrow_mut().read_exact(&mut data)?;
        Ok(data[0] != 0)
    }

    /// Write a `Block` to the channel.
    #[inline(always)]
    pub fn write_block(&mut self, b: &Block) -> Result<usize> {
        self.writer.borrow_mut().write(b.as_ref())
    }

    /// Read a `Block` from the channel.
    #[inline(always)]
    pub fn read_block(&mut self) -> Result<Block> {
        let mut v = Block::default();
        self.reader.borrow_mut().read_exact(v.as_mut())?;
        Ok(v)
    }

    /// Write a `Block512` to the channel.
    #[inline(always)]
    pub fn write_block512(&mut self, b: &Block512) -> Result<usize> {
        for block in b.0.iter() {
            self.write_block(block)?;
        }
        Ok(64)
    }

    /// Read a `Block512` from the channel.
    #[inline(always)]
    pub fn read_block512(&mut self) -> Result<Block512> {
        let mut data = [0u8; 64];
        self.reader.borrow_mut().read_exact(&mut data)?;
        Ok(Block512::from(data))
    }

    /// Write a slice of `u8`s to the channel.
    #[inline(always)]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize> {
        self.writer.borrow_mut().write(bytes)
    }

    /// Read a slice of `u8`s from the channel.
    #[inline(always)]
    pub fn read_bytes_inplace(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.borrow_mut().read_exact(&mut bytes)
    }

    /// Write a `RistrettoPoint` to the channel.
    #[cfg(feature = "curve25519-dalek")]
    #[inline(always)]
    pub fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize> {
        self.writer.borrow_mut().write(pt.compress().as_bytes())
    }

    /// Read a `RistrettoPoint` from the channel.
    #[cfg(feature = "curve25519-dalek")]
    #[inline(always)]
    pub fn read_pt(&mut self) -> Result<RistrettoPoint> {
        let mut data = [0u8; 32];
        self.reader.borrow_mut().read_exact(&mut data)?;
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

    /// Flush the channel.
    #[inline(always)]
    pub fn flush(&mut self) -> Result<()> {
        self.writer.borrow_mut().flush()
    }
}

// pub struct TrackChannel<R: Read, W: Write> {
//     pub channel: Channel<TrackReader<R>, TrackWriter<W>>,
// }

// impl<R: Read, W: Write> TrackChannel<R, W> {
//     pub fn new(reader: R, writer: W) -> Self {
//         let channel = Channel::new(TrackReader::new(reader), TrackWriter::new(writer));
//         Self { channel }
//     }
// }
