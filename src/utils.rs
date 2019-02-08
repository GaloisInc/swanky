// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::aes::Aes128;
use crate::Block;
use arrayref::array_ref;
use core::arch::x86_64::*;
use curve25519_dalek::ristretto::RistrettoPoint;

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

// #[inline(always)]
// pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
//     a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
// }

#[inline(always)]
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

#[inline(always)]
pub fn xor_block(x: &Block, y: &Block) -> Block {
    unsafe {
        let z = _mm_xor_si128(block_to_m128i(x), block_to_m128i(y));
        m128i_to_block(z)
    }
}

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
pub fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    let m_ = vec![0u8; nrows * ncols / 8];
    unsafe {
        sse_trans(
            m_.as_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        )
    };
    m_
}

#[link(name = "transpose")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

#[inline(always)]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let mut v = vec![0u8; bv.len() / 8];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}
#[inline(always)]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
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

    #[test]
    fn test_transpose() {
        let (nrows, ncols) = (128, 1 << 15);
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        let m_ = m.clone();
        let m = transpose(&m, nrows, ncols);
        let m = transpose(&m, ncols, nrows);
        assert_eq!(m, m_);
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
    fn bench_xor_inplace(b: &mut Bencher) {
        let mut x = rand::random::<[u8; 16]>().to_vec();
        let y = rand::random::<[u8; 16]>().to_vec();
        b.iter(|| xor_inplace(&mut x, &y));
    }

    #[bench]
    fn bench_xor_block(b: &mut Bencher) {
        let x = rand::random::<[u8; 16]>();
        let y = rand::random::<[u8; 16]>();
        b.iter(|| xor_block(&x, &y));
    }

    #[bench]
    fn bench_tranpose(b: &mut Bencher) {
        let (nrows, ncols) = (128, 1 << 15);
        let m = vec![0u8; nrows * ncols / 8];
        b.iter(|| transpose(&m, nrows, ncols));
    }
}
