// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Defines a 512-bit value.

use crate::Block;
use std::arch::x86_64::*;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};

/// A 512-bit value.
#[derive(Clone, Copy)]
pub struct Block512([Block; 4]);

impl Block512 {
    /// Make a new `Block512` from `v`.
    #[inline]
    pub fn new(v: [u8; 64]) -> Self {
        unsafe { std::mem::transmute(v) }
        // unsafe { Self(*(&v as *const u8 as *const [Block; 4])) }
    }
    /// Read a `Block512` from `reader`.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        let mut data = [0u8; 64];
        reader.read_exact(&mut data)?;
        Ok(Self::new(data))
    }
    /// Write a `Block512` to `writer`.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        for block in self.0.iter() {
            block.write(writer)?;
        }
        Ok(())
    }
    /// Return the first `n` bytes, where `n` must be `<= 64`.
    #[inline]
    pub fn prefix(&self, n: usize) -> &[u8] {
        debug_assert!(n <= 64);
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, n) }
    }

    /// Return the first `n` bytes as mutable, where `n` must be `<= 64`.
    #[inline]
    pub fn prefix_mut(&mut self, n: usize) -> &mut [u8] {
        debug_assert!(n <= 64);
        unsafe { std::slice::from_raw_parts_mut(self as *mut Self as *mut u8, n) }
    }
}

impl AsMut<[u8]> for Block512 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.prefix_mut(64)
    }
}

impl AsRef<[u8]> for Block512 {
    fn as_ref(&self) -> &[u8] {
        self.prefix(64)
    }
}

impl std::ops::BitXor for Block512 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        let b0 = self.0[0] ^ rhs.0[0];
        let b1 = self.0[1] ^ rhs.0[1];
        let b2 = self.0[2] ^ rhs.0[2];
        let b3 = self.0[3] ^ rhs.0[3];
        Self([b0, b1, b2, b3])
    }
}

impl std::ops::BitXorAssign for Block512 {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl Default for Block512 {
    fn default() -> Self {
        Self([
            Block::default(),
            Block::default(),
            Block::default(),
            Block::default(),
        ])
    }
}

impl std::fmt::Debug for Block512 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl std::fmt::Display for Block512 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl rand::distributions::Distribution<Block512> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block512 {
        let b1 = rng.gen::<Block>();
        let b2 = rng.gen::<Block>();
        let b3 = rng.gen::<Block>();
        let b4 = rng.gen::<Block>();
        Block512([b1, b2, b3, b4])
    }
}

impl Eq for Block512 {}

impl From<Block512> for [u32; 16] {
    #[inline]
    fn from(m: Block512) -> [u32; 16] {
        unsafe { *(&m.0 as *const _ as *const [u32; 16]) }
    }
}

impl From<Block512> for [__m128i; 4] {
    #[inline]
    fn from(m: Block512) -> [__m128i; 4] {
        [m.0[0].into(), m.0[1].into(), m.0[2].into(), m.0[3].into()]
    }
}

impl From<[__m128i; 4]> for Block512 {
    #[inline]
    fn from(m: [__m128i; 4]) -> Block512 {
        Block512([Block(m[0]), Block(m[1]), Block(m[2]), Block(m[3])])
    }
}

impl From<[Block; 4]> for Block512 {
    #[inline]
    fn from(m: [Block; 4]) -> Block512 {
        Block512([m[0], m[1], m[2], m[3]])
    }
}

#[cfg(feature = "nightly")]
impl From<Block512> for __m512i {
    #[inline]
    fn from(m: Block512) -> __m512i {
        unsafe { std::mem::transmute(m) }
        // unsafe { *(&m as *const _ as *const __m512i) }
    }
}

#[cfg(feature = "nightly")]
impl From<__m512i> for Block512 {
    #[inline]
    fn from(m: __m512i) -> Block512 {
        Block512(unsafe { *(&m as *const _ as *const [Block; 4]) })
    }
}

impl Hash for Block512 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Ord for Block512 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq for Block512 {
    fn eq(&self, other: &Block512) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for Block512 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}
