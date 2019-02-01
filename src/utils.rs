// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::aes::Aes128;
use aesni::stream_cipher::{NewStreamCipher, StreamCipher};
use aesni::Aes128Ctr;
use arrayref::array_ref;
use core::arch::x86_64::*;
use curve25519_dalek::ristretto::RistrettoPoint;

#[inline(always)]
pub fn hash_pt(pt: &RistrettoPoint, nbytes: usize) -> Vec<u8> {
    let k = pt.compress();
    let k = k.as_bytes();
    let mut m = vec![0u8; nbytes];
    encrypt(&k[0..16], &k[16..32], &mut m);
    m
}
#[inline(always)]
pub fn hash_pt_inplace(pt: &RistrettoPoint, out: &mut [u8]) {
    let k = pt.compress();
    let k = k.as_bytes();
    let mut m = vec![0u8; out.len()];
    encrypt(&k[0..16], &k[16..32], &mut m);
    unsafe { std::ptr::copy_nonoverlapping(m.as_ptr(), out.as_mut_ptr(), out.len()) };
}

#[inline(always)]
pub fn hash_pt_128(pt: &RistrettoPoint, _nbytes: usize) -> Vec<u8> {
    let k = pt.compress();
    let k = k.as_bytes();
    let c = Aes128::new(array_ref![k, 0, 16]);
    let m = [0u8; 16];
    let m = c.encrypt_u8(&m);
    m.to_vec()
}
#[inline(always)]
pub fn hash_pt_128_inplace(pt: &RistrettoPoint, out: &mut [u8]) {
    let k = pt.compress();
    let k = k.as_bytes();
    let c = Aes128::new(array_ref![k, 0, 16]);
    let m = [0u8; 16];
    let m = c.encrypt_u8(&m);
    unsafe { std::ptr::copy_nonoverlapping(m.as_ptr(), out.as_mut_ptr(), 16) };
}

#[inline(always)]
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[inline(always)]
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

#[inline(always)]
pub fn xor_block(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    unsafe {
        let z = _mm_xor_si128(u8x16_to_m128i(x), u8x16_to_m128i(y));
        m128i_to_u8x16(z)
    }
}

type Cipher = Aes128Ctr;

#[inline(always)]
pub fn encrypt(k: &[u8], iv: &[u8], mut m: &mut [u8]) {
    let mut cipher = Cipher::new_var(k, iv).unwrap();
    cipher.encrypt(&mut m)
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
#[inline(always)]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let mut v = vec![0u8; bv.len() / 8];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}
#[inline(always)]
pub fn u8x16_to_m128i(v: &[u8; 16]) -> __m128i {
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(*v) }
}
#[inline(always)]
pub fn m128i_to_u8x16(m: __m128i) -> [u8; 16] {
    unsafe { std::mem::transmute::<__m128i, [u8; 16]>(m) }
}

#[link(name = "transpose")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;

    #[test]
    fn test_xor_block() {
        let x = rand::random::<[u8; 16]>();
        let y = rand::random::<[u8; 16]>();
        let z = xor_block(&x, &y);
        let z = xor_block(array_ref![z, 0, 16], &y);
        assert_eq!(x, *array_ref![z, 0, 16]);
    }
}
