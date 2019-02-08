// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of a random number generator based on fixed-key AES.

use crate::aes::Aes128;
use crate::utils;
use crate::Block;
use core::arch::x86_64::*;

/// AES-based random number generator.
pub struct AesRng {
    aes: Aes128,
}

impl AesRng {
    #[inline(always)]
    pub fn new(seed: &Block) -> Self {
        let aes = Aes128::new(&seed);
        AesRng { aes }
    }

    /// Fills `bytes` with random bits.
    ///
    /// This uses AES in a counter-mode-esque way, but with the counter always
    /// starting at zero. When used as a PRNG this is okay [TODO: citation?].
    #[inline(always)]
    pub fn random(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len() % 16, 0);
        for (i, m) in bytes.chunks_mut(16).enumerate() {
            let data = unsafe { _mm_set_epi64(_mm_setzero_si64(), _mm_set_pi32(0, i as i32)) };
            let c = self.aes.encrypt_u8(&utils::m128i_to_block(data));
            unsafe { std::ptr::copy_nonoverlapping(c.as_ptr(), m.as_mut_ptr(), 16) };
        }
    }
}

#[cfg(test)]
mod benchamarks {
    extern crate test;

    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_aes_rand(b: &mut Bencher) {
        let rng = AesRng::new(&rand::random::<[u8; 16]>());
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.random(&mut x));
    }
}
