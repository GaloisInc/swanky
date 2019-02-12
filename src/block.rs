// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Defines a block as a 128-bit value, and implements block-related functions.

use crate::aes::Aes128;
use arrayref::array_ref;
use core::arch::x86_64::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use failure::Error;
use std::io::{BufReader, BufWriter, Read, Write};

/// A 128-bit chunk.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Block([u8; 16]);

impl Block {
    #[inline(always)]
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    #[inline(always)]
    pub fn zero() -> Self {
        unsafe { Block::from(_mm_setzero_si128()) }
    }
}

impl AsRef<[u8]> for Block {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Block {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl std::ops::BitXor for Block {
    type Output = Block;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        unsafe {
            let z = _mm_xor_si128(self.into(), rhs.into());
            Block::from(z)
        }
    }
}

impl rand::distributions::Distribution<Block> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block(rng.gen::<[u8; 16]>())
    }
}

// Fixed key for AES hash. This is the same fixed key as used in the EMP toolkit.
pub const FIXED_KEY: Block = Block([
    0x61, 0x7e, 0x8d, 0xa2, 0xa0, 0x51, 0x1e, 0x96, 0x5e, 0x41, 0xc2, 0x9b, 0x15, 0x3f, 0xc7, 0x7a,
]);

#[inline(always)]
pub fn write_block<T: Read + Write + Send>(
    stream: &mut BufWriter<T>,
    block: &Block,
) -> Result<usize, Error> {
    stream.write(&block.0).map_err(Error::from)
}
#[inline(always)]
pub fn read_block<T: Read + Write + Send>(stream: &mut BufReader<T>) -> Result<Block, Error> {
    let mut v = Block::zero();
    stream.read_exact(&mut v.0)?;
    Ok(v)
}

impl Into<__m128i> for Block {
    #[inline(always)]
    fn into(self) -> __m128i {
        unsafe { std::mem::transmute::<Block, __m128i>(self) }
    }
}

impl From<__m128i> for Block {
    #[inline(always)]
    fn from(m: __m128i) -> Self {
        unsafe { std::mem::transmute::<__m128i, Block>(m) }
    }
}

impl Into<[u8; 16]> for Block {
    #[inline(always)]
    fn into(self) -> [u8; 16] {
        self.0
    }
}

impl From<[u8; 16]> for Block {
    #[inline(always)]
    fn from(m: [u8; 16]) -> Self {
        Block(m)
    }
}

#[inline(always)]
pub fn xor_two_blocks(x: &(Block, Block), y: &(Block, Block)) -> (Block, Block) {
    unsafe {
        let z0 = _mm_xor_si128(x.0.into(), y.0.into());
        let z1 = _mm_xor_si128(x.1.into(), y.1.into());
        (Block::from(z0), Block::from(z1))
    }
}

/// Hash an elliptic curve point `pt` by computing `E_{pt}(i)`, where `E` is
/// AES-128 and `i` is an index.
#[inline(always)]
pub fn hash_pt_block(i: usize, pt: &RistrettoPoint) -> Block {
    let k = pt.compress();
    let k = k.as_bytes();
    let c = Aes128::new(&Block(*array_ref![k, 0, 16]));
    unsafe {
        let m = _mm_set_epi64(_mm_setzero_si64(), std::mem::transmute::<usize, __m64>(i));
        c.encrypt_u8(&Block::from(m))
    }
}

/// Carryless multiplication. This code is adapted from the EMP toolkit's
/// implementation.
#[inline(always)]
pub fn mul128(x: Block, y: Block) -> (Block, Block) {
    unsafe {
        let x = std::mem::transmute::<Block, __m128i>(x);
        let y = std::mem::transmute::<Block, __m128i>(y);
        let zero = _mm_clmulepi64_si128(x, y, 0x00);
        let one = _mm_clmulepi64_si128(x, y, 0x01);
        let two = _mm_clmulepi64_si128(x, y, 0x10);
        let three = _mm_clmulepi64_si128(x, y, 0x11);
        let tmp = _mm_xor_si128(one, two);
        let ll = _mm_slli_si128(tmp, 8);
        let rl = _mm_srli_si128(tmp, 8);
        let x = _mm_xor_si128(zero, ll);
        let y = _mm_xor_si128(three, rl);
        let x = std::mem::transmute::<__m128i, Block>(x);
        let y = std::mem::transmute::<__m128i, Block>(y);
        (x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_block() {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        let z = x ^ y;
        let z = z ^ y;
        assert_eq!(x, z);
    }
}

#[cfg(test)]
mod benchamarks {
    extern crate test;

    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_hash_pt_block(b: &mut Bencher) {
        let pt = RistrettoPoint::random(&mut rand::thread_rng());
        let i = rand::random::<usize>();
        b.iter(|| hash_pt_block(i, &pt));
    }

    #[bench]
    fn bench_xor_block(b: &mut Bencher) {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| x ^ y);
    }

    #[bench]
    fn bench_mul128(b: &mut Bencher) {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| mul128(x, y));
    }
}
