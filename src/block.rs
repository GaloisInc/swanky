// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::aes::Aes128;
use arrayref::array_ref;
use core::arch::x86_64::*;
use curve25519_dalek::ristretto::RistrettoPoint;

/// A 128-bit chunk.
pub type Block = [u8; 16];

#[inline(always)]
pub fn zero_block() -> Block {
    unsafe { m128i_to_block(_mm_setzero_si128()) }
}

#[inline(always)]
pub fn block_to_m128i(v: &Block) -> __m128i {
    unsafe { std::mem::transmute::<Block, __m128i>(*v) }
}
#[inline(always)]
pub fn m128i_to_block(m: __m128i) -> Block {
    unsafe { std::mem::transmute::<__m128i, Block>(m) }
}

#[inline(always)]
pub fn xor_block(x: &Block, y: &Block) -> Block {
    unsafe {
        let z = _mm_xor_si128(block_to_m128i(x), block_to_m128i(y));
        m128i_to_block(z)
    }
}

#[inline(always)]
pub fn xor_two_blocks(x: &(Block, Block), y: &(Block, Block)) -> (Block, Block) {
    unsafe {
        let z0 = _mm_xor_si128(block_to_m128i(&x.0), block_to_m128i(&y.0));
        let z1 = _mm_xor_si128(block_to_m128i(&x.1), block_to_m128i(&y.1));
        (m128i_to_block(z0), m128i_to_block(z1))
    }
}

/// Hash an elliptic curve point `pt` by computing `E_{pt}(i)`, where `E` is
/// AES-128 and `i` is an index.
#[inline(always)]
pub fn hash_pt_block(i: usize, pt: &RistrettoPoint) -> Block {
    let k = pt.compress();
    let k = k.as_bytes();
    let c = Aes128::new(array_ref![k, 0, 16]);
    unsafe {
        let m = _mm_set_epi64(_mm_setzero_si64(), std::mem::transmute::<usize, __m64>(i));
        c.encrypt_u8(&m128i_to_block(m))
    }
}

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
        let x = rand::random::<[u8; 16]>();
        let y = rand::random::<[u8; 16]>();
        let z = xor_block(&x, &y);
        let z = xor_block(&z, &y);
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
        let x = rand::random::<[u8; 16]>();
        let y = rand::random::<[u8; 16]>();
        b.iter(|| xor_block(&x, &y));
    }
}
