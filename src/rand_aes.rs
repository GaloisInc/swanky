// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of a random number generator based on fixed-key AES.
//!
//! This uses AES in a counter-mode-esque way, but with the counter always
//! starting at zero. When used as a PRNG this is okay [TODO: citation?].

use crate::aes::Aes128;
use crate::utils;
use crate::Block;
use core::arch::x86_64::*;
use core::fmt;
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};

#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl RngCore for AesRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl SeedableRng for AesRng {
    type Seed = <AesRngCore as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::<AesRngCore>::from_seed(seed))
    }

    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng::<AesRngCore>::from_rng(rng).map(AesRng)
    }
}

impl CryptoRng for AesRng {}

impl AesRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    pub fn new() -> Self {
        let seed = rand::random::<Block>();
        AesRng::from_seed(seed)
    }
}

/// AES-based random number generator.
#[derive(Clone)]
pub struct AesRngCore {
    aes: Aes128,
    state: u64,
}

impl fmt::Debug for AesRngCore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AesRngCore {{}}")
    }
}

impl BlockRngCore for AesRngCore {
    type Item = u32;
    // This is equivalent to `[u8; 16]`, but we need to use `u32` to be
    // compatible with `RngCore`.
    type Results = [u32; 4];

    fn generate(&mut self, results: &mut Self::Results) {
        let data = unsafe { _mm_set_epi64(_mm_setzero_si64(), _mm_set_pi32(0, self.state as i32)) };
        let c = self.aes.encrypt_u8(&utils::m128i_to_block(data));
        unsafe {
            let mut results = std::mem::transmute::<[u32; 4], Block>(*results);
            std::ptr::copy_nonoverlapping(c.as_ptr(), results.as_mut_ptr(), 16)
        };
        self.state = self.state.wrapping_add(1);
    }
}

impl SeedableRng for AesRngCore {
    type Seed = Block;

    #[inline(always)]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = Aes128::new(&seed);
        AesRngCore { aes, state: 0 }
    }
}

impl CryptoRng for AesRngCore {}

impl From<AesRngCore> for AesRng {
    fn from(core: AesRngCore) -> Self {
        AesRng(BlockRng::new(core))
    }
}

#[cfg(test)]
mod benchamarks {
    extern crate test;

    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_aes_rand(b: &mut Bencher) {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(&mut x));
    }
}
