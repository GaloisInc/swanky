// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#[inline(always)]
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
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
    fn test_transpose() {
        let (nrows, ncols) = (128, 1 << 16);
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        let m_ = m.clone();
        let m = transpose(&m, nrows, ncols);
        let m = transpose(&m, ncols, nrows);
        assert_eq!(m, m_);
    }

    #[test]
    fn test_boolvec_to_u8vec() {
        let v = (0..128)
            .map(|_| rand::random::<bool>())
            .collect::<Vec<bool>>();
        let v_ = boolvec_to_u8vec(&v);
        let v__ = u8vec_to_boolvec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = u8vec_to_boolvec(&v);
        let v__ = boolvec_to_u8vec(&v_);
        assert_eq!(v, v__);
    }
}

#[cfg(test)]
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
    fn bench_tranpose(b: &mut Bencher) {
        let (nrows, ncols) = (128, 1 << 16);
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| transpose(&m, nrows, ncols));
    }
}
