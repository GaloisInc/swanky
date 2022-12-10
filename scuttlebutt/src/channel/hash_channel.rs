// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Block;
use crate::{AbstractChannel, Channel};
use sha2::{Digest, Sha256};
use std::io::{Read, Result, Write};

use super::GetBlockByIndex;

/// An instantiation of the `AbstractChannel` trait which computes a running
/// hash of all bytes read from and written to the channel.
pub struct HashChannel<R: GetBlockByIndex, W> {
    channel: Channel<R, W>,
    hash: Sha256,
}

impl<R: Read + GetBlockByIndex, W: Write> HashChannel<R, W> {
    /// Make a new `HashChannel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let channel = Channel::new(reader, writer);
        let hash = Sha256::new();
        Self { channel, hash }
    }

    /// Consume the channel and output the hash of all the communication.
    pub fn finish(self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.hash.result());
        h
    }
}

impl<R: Read + GetBlockByIndex, W: Write> AbstractChannel for HashChannel<R, W> {
    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.hash.input(bytes);
        self.channel.write_bytes(bytes)
    }

    #[inline]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.channel.read_bytes(&mut bytes)?;
        self.hash.input(&bytes);
        Ok(())
    }

    // #[inline]
    // fn flush(&mut self) -> Result<()> {
    //     self.channel.flush()
    // }

    // #[inline]
    // fn clone(&self) -> Self {
    //     Self {
    //         channel: self.channel.clone(),
    //         hash: self.hash.clone(),
    //     }
    // }
}
