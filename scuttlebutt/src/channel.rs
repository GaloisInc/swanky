// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

mod hash_channel;
mod sync_channel;
mod track_channel;
#[cfg(unix)]
mod unix_channel;

pub use hash_channel::HashChannel;
pub use sync_channel::SyncChannel;
pub use track_channel::TrackChannel;

#[cfg(unix)]
pub use unix_channel::{track_unix_channel_pair, unix_channel_pair, TrackUnixChannel, UnixChannel};

use crate::{Block, Block512};
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::{
    cell::RefCell,
    io::{Read, Result, Write},
    rc::Rc,
};

pub trait Sendable {
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()>;
}

pub trait Receivable: Sized {
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self>;
}

impl<'a> Sendable for &bool {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(*self)
    }
}

impl<'a> Sendable for bool {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&[self as u8])
    }
}

impl Receivable for bool {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        chan.receive::<[u8; 1]>().map(|b| b[0] != 0x0)
    }
}

impl<const N: usize> Receivable for [u8; N] {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        let mut elems: [u8; N] = [0u8; N];
        chan.read_bytes(&mut elems)?;
        Ok(elems)
    }
}

impl<'a, const N: usize> Sendable for &'a [u8; N] {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.write_bytes(self)
    }
}

impl<T: Receivable> Receivable for (T, T) {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        Ok((chan.receive()?, chan.receive()?))
    }
}

impl<T: Receivable + Default + Copy, const N: usize> Receivable for [T; N] {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        let mut elems: [T; N] = [Default::default(); N];
        for elem in elems.iter_mut() {
            *elem = chan.receive()?;
        }
        Ok(elems)
    }
}

impl<'a, T> Sendable for &'a [T]
where
    &'a T: Sendable,
{
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        for elem in self.iter() {
            chan.send(elem)?;
        }
        Ok(())
    }
}

impl<'a, T, const N: usize> Sendable for &'a [T; N]
where
    &'a T: Sendable,
{
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        for elem in self.iter() {
            chan.send(elem)?;
        }
        Ok(())
    }
}

// The Rust type inference goes depth-first into this and dies:
// since the type does not become smaller, it causes infinite recursion when
// looking for an implementation of Sendable for &'a T.
// Can we enforce that T not be a reference?
/*
impl<'a, T> Sendable for T
where
    &'a T: Sendable,
{
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self)
    }
}
*/

impl<'a, T1, T2> Sendable for &'a (T1, T2)
where
    &'a T1: Sendable,
    &'a T2: Sendable,
{
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self.0)?;
        chan.send(&self.1)
    }
}

impl<'a> Sendable for &Block {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.write_bytes(self.as_ref())
    }
}

impl Receivable for Block {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        let mut v = Block::default();
        chan.read_bytes(v.as_mut())?;
        Ok(v)
    }
}

impl<'a> Sendable for &'a Block512 {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self.0[0])?;
        chan.send(&self.0[1])?;
        chan.send(&self.0[2])?;
        chan.send(&self.0[3])
    }
}

impl Receivable for Block512 {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        Ok(Block512([
            chan.receive()?,
            chan.receive()?,
            chan.receive()?,
            chan.receive()?,
        ]))
    }
}

impl Sendable for u16 {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self.to_le_bytes())
    }
}

impl Receivable for u16 {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        chan.receive::<[u8; 2]>().map(|b| u16::from_le_bytes(b))
    }
}

impl Sendable for u32 {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self.to_le_bytes())
    }
}

impl Receivable for u32 {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        chan.receive::<[u8; 4]>().map(|b| u32::from_le_bytes(b))
    }
}

impl Sendable for u64 {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(&self.to_le_bytes())
    }
}

impl Receivable for u64 {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        chan.receive::<[u8; 8]>().map(|b| u64::from_le_bytes(b))
    }
}

impl Sendable for usize {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.send(self as u64)
    }
}

impl Receivable for usize {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        chan.receive::<u64>().map(|v| v as usize)
    }
}

#[cfg(feature = "curve25519-dalek")]
impl<'a> Sendable for &'a RistrettoPoint {
    #[inline(always)]
    fn send<C: AbstractChannel>(self, chan: &mut C) -> Result<()> {
        chan.write_bytes(self.compress().as_bytes())
    }
}

#[cfg(feature = "curve25519-dalek")]
impl Receivable for RistrettoPoint {
    #[inline(always)]
    fn receive<C: AbstractChannel>(chan: &mut C) -> Result<Self> {
        let data: [u8; 32] = chan.receive()?;
        CompressedRistretto::from_slice(&data)
            .decompress()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unable to decompress ristretto point",
                )
            })
    }
}

/// A trait for managing I/O. `AbstractChannel`s are clonable, and provide basic
/// read/write capabilities for both common and scuttlebutt-specific types.
pub trait AbstractChannel: Clone {
    /// Read a slice of `u8`s from the channel.
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;

    /// Write a slice of `u8`s to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;

    /// Flush the channel.
    fn flush(&mut self) -> Result<()>;

    /// Receive a value from the channel
    fn receive<R: Receivable>(&mut self) -> Result<R> {
        R::receive(self)
    }

    /// Receive n instances of a type from the channel
    fn receive_n<R: Receivable>(&mut self, n: usize) -> Result<Vec<R>> {
        let mut elems = Vec::with_capacity(n);
        for _ in 0..n {
            elems.push(R::receive(self)?);
        }
        Ok(elems)
    }

    /// Send a value to the channel (by reference or by value)
    fn send<S: Sendable>(&mut self, value: S) -> Result<()> {
        value.send(self)
    }

    /// Read `nbytes` from the channel, and return it as a `Vec`.
    fn read_vec(&mut self, nbytes: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; nbytes];
        self.read_bytes(&mut data)?;
        Ok(data)
    }
}

/// A standard read/write channel that implements `AbstractChannel`.
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
    pub fn reader(self) -> Rc<RefCell<R>> {
        self.reader
    }

    /// Return a writer object wrapped in `Rc<RefCell>`.
    pub fn writer(self) -> Rc<RefCell<W>> {
        self.writer
    }
}

impl<R: Read, W: Write> Clone for Channel<R, W> {
    fn clone(&self) -> Self {
        Channel {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl<R: Read, W: Write> AbstractChannel for Channel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.borrow_mut().write_all(bytes)?;
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
}

/// Standard Read/Write channel built from a symmetric stream.
pub struct SymChannel<S: Read + Write> {
    stream: Rc<RefCell<S>>,
}

impl<S: Read + Write> SymChannel<S> {
    /// Make a new `Channel` from a stream.
    pub fn new(stream: S) -> Self {
        let stream = Rc::new(RefCell::new(stream));
        Self { stream }
    }
}

impl<S: Read + Write> AbstractChannel for SymChannel<S> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.borrow_mut().write_all(bytes)?;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.stream.borrow_mut().read_exact(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.stream.borrow_mut().flush()
    }
}

impl<S: Read + Write> Clone for SymChannel<S> {
    fn clone(&self) -> Self {
        SymChannel {
            stream: self.stream.clone(),
        }
    }
}
