// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Defines a block as a 128-bit value, and implements block-related functions.

#[cfg(feature = "curve25519-dalek")]
use crate::aes::Aes128;
#[cfg(any(feature = "curve25519-dalek", feature = "serde"))]
use arrayref::array_ref;
use core::arch::x86_64::*;
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::RistrettoPoint;
use failure::Error;
use std::io::{Read, Write};

/// A 128-bit chunk.
#[derive(Clone, Copy, Debug)]
pub struct Block(pub(crate) __m128i);

impl Block {
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut().as_mut_ptr()
    }
    /// Output the all-zero block.
    #[inline]
    pub fn zero() -> Self {
        unsafe { Block(_mm_setzero_si128()) }
    }
    /// Carryless multiplication. This code is adapted from the EMP toolkit's
    /// implementation.
    #[inline]
    pub fn mul128(self, rhs: Self) -> (Self, Self) {
        unsafe {
            let x = self.0;
            let y = rhs.0;
            let zero = _mm_clmulepi64_si128(x, y, 0x00);
            let one = _mm_clmulepi64_si128(x, y, 0x01);
            let two = _mm_clmulepi64_si128(x, y, 0x10);
            let three = _mm_clmulepi64_si128(x, y, 0x11);
            let tmp = _mm_xor_si128(one, two);
            let ll = _mm_slli_si128(tmp, 8);
            let rl = _mm_srli_si128(tmp, 8);
            let x = _mm_xor_si128(zero, ll);
            let y = _mm_xor_si128(three, rl);
            (Block(x), Block(y))
        }
    }
    /// Hash an elliptic curve point `pt` by computing `E_{pt}(i)`, where `E` is
    /// AES-128 and `i` is an index.
    #[cfg(feature = "curve25519-dalek")]
    #[inline]
    pub fn hash_pt(i: usize, pt: &RistrettoPoint) -> Self {
        let k = pt.compress();
        let k = k.as_bytes();
        // XXX: We're just taking the first 16 bytes of the compressed point... Is that secure?!
        let c = Aes128::new(Block::from(*array_ref![k, 0, 16]));
        let m =
            unsafe { _mm_set_epi64(_mm_setzero_si64(), std::mem::transmute::<usize, __m64>(i)) };
        c.encrypt(Block(m))
    }

    // Fixed key for AES hash. This is the same fixed key as used in the EMP toolkit.
    #[inline]
    pub fn fixed_key() -> Self {
        Block::from([
            0x61, 0x7e, 0x8d, 0xa2, 0xa0, 0x51, 0x1e, 0x96, 0x5e, 0x41, 0xc2, 0x9b, 0x15, 0x3f,
            0xc7, 0x7a,
        ])
    }
    #[inline]
    pub fn write<T: Write>(&self, stream: &mut T) -> Result<usize, Error> {
        stream.write(self.as_ref()).map_err(Error::from)
    }
    #[inline]
    pub fn read<T: Read>(stream: &mut T) -> Result<Block, Error> {
        let mut v = Block::zero();
        stream.read_exact(v.as_mut())?;
        Ok(v)
    }
}

impl Default for Block {
    #[inline]
    fn default() -> Self {
        Block::zero()
    }
}

impl PartialEq for Block {
    #[inline]
    fn eq(&self, other: &Block) -> bool {
        unsafe {
            let neq = _mm_xor_si128(self.0, other.0);
            _mm_test_all_zeros(neq, neq) != 0
        }
    }
}

impl AsRef<[u8]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { &*(self as *const Block as *const [u8; 16]) }
    }
}

impl AsMut<[u8]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *(self as *mut Block as *mut [u8; 16]) }
    }
}

impl std::ops::BitXor for Block {
    type Output = Block;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        unsafe { Block(_mm_xor_si128(self.0, rhs.0)) }
    }
}

impl rand::distributions::Distribution<Block> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::from(rng.gen::<[u8; 16]>())
    }
}

impl From<Block> for u128 {
    #[inline]
    fn from(m: Block) -> u128 {
        unsafe { std::mem::transmute(m.0) }
    }
}

impl From<u128> for Block {
    #[inline]
    fn from(m: u128) -> Self {
        unsafe { Block(std::mem::transmute(m)) }
    }
}

impl From<Block> for __m128i {
    #[inline]
    fn from(m: Block) -> __m128i {
        m.0
    }
}

impl From<__m128i> for Block {
    #[inline]
    fn from(m: __m128i) -> Self {
        Block(m)
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(m: Block) -> [u8; 16] {
        unsafe { std::mem::transmute(m) }
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(m: [u8; 16]) -> Self {
        unsafe { std::mem::transmute(m) }
    }
}

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for Block {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&unsafe { std::mem::transmute::<__m128i, [u8; 16]>(self.0) })
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Block {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlockVisitor;
        impl<'de> Visitor<'de> for BlockVisitor {
            type Value = Block;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a 128-bit chunk")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Block, E> {
                if v.len() == 16 {
                    Ok(Block::from(*array_ref![v, 0, 16]))
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(BlockVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        let z = x ^ y;
        let z = z ^ y;
        assert_eq!(x, z);
    }
}
