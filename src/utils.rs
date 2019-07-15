// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Useful utility functions.

#[inline]
/// XOR two byte arrays, outputting the result.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[inline]
/// XOR two byte arrays up to `n` bytes, outputting the result.
pub fn xor_n(a: &[u8], b: &[u8], n: usize) -> Vec<u8> {
    a[0..n]
        .iter()
        .zip(b[0..n].iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// XOR two byte arrays in place.
#[inline]
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

#[inline]
/// XOR two byte arrays up to `n` bytes in place.
pub fn xor_inplace_n(a: &mut [u8], b: &[u8], n: usize) {
    for (a, b) in a[0..n].iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

#[inline]
/// AND two byte arrays, outputting the result.
pub fn and(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a & b).collect()
}

#[inline]
/// AND two byte arrays in place.
pub fn and_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a &= *b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v__ = xor(&v, &v_);
        let v___ = xor(&v__, &v_);
        assert_eq!(v___, v);
    }

    #[test]
    fn test_xor_inplace() {
        let mut v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let goal = v.clone();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        xor_inplace(&mut v, &v_);
        xor_inplace(&mut v, &v_);
        assert_eq!(v, goal);
    }

    #[test]
    fn test_and() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| 0xFF).collect::<Vec<u8>>();
        let v__ = and(&v, &v_);
        assert_eq!(v__, v);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_xor_inplace(b: &mut Bencher) {
        let mut x = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let y = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        b.iter(|| xor_inplace(&mut x, &y));
    }

    #[bench]
    fn bench_and_inplace(b: &mut Bencher) {
        let mut x = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let y = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        b.iter(|| and_inplace(&mut x, &y));
    }

}
