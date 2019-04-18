// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Fixed-key AES random number generator.

use crate::{Aes128, Block};
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};
#[cfg(feature = "nightly")]
use std::arch::x86_64::*;

/// Implementation of a random number generator based on fixed-key AES.
///
/// This uses AES in a counter-mode-esque way, but with the counter always
/// starting at zero. When used as a PRNG this is okay [TODO: citation?].
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl RngCore for AesRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl SeedableRng for AesRng {
    type Seed = <AesRngCore as SeedableRng>::Seed;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::<AesRngCore>::from_seed(seed))
    }
    #[inline]
    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng::<AesRngCore>::from_rng(rng).map(AesRng)
    }
}

impl CryptoRng for AesRng {}

impl AesRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    #[inline]
    pub fn new() -> Self {
        let seed = rand::random::<Block>();
        AesRng::from_seed(seed)
    }
}

impl Default for AesRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of `AesRng`, used with `BlockRng`.
#[derive(Clone)]
pub struct AesRngCore {
    aes: Aes128,
    #[cfg(feature = "nightly")]
    state: __m64,
    #[cfg(not(feature = "nightly"))]
    state: u64,
}

impl std::fmt::Debug for AesRngCore {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "AesRngCore {{}}")
    }
}

impl BlockRngCore for AesRngCore {
    type Item = u32;
    // This is equivalent to `[u8; 16]`, but we need to use `u32` to be
    // compatible with `RngCore`.
    type Results = [u32; 4];

    // Compute `E(state)`, where `state` is a counter initialized to zero.
    #[inline]
    #[cfg(feature = "nightly")]
    fn generate(&mut self, results: &mut Self::Results) {
        let m0 = unsafe { _mm_set_epi64(_mm_setzero_si64(), self.state) };
        self.state = unsafe { _mm_add_pi32(self.state, _mm_set_pi32(0, 1)) };
        *results = self.aes.encrypt(Block(m0)).into();
        // let m0 = unsafe { _mm_set_epi64(_mm_setzero_si64(), self.state) };
        // self.state = unsafe { _mm_add_pi32(self.state, _mm_set_pi32(0, 1)) };
        // let m1 = unsafe { _mm_set_epi64(_mm_setzero_si64(), self.state) };
        // self.state = unsafe { _mm_add_pi32(self.state, _mm_set_pi32(0, 1)) };
        // let m2 = unsafe { _mm_set_epi64(_mm_setzero_si64(), self.state) };
        // self.state = unsafe { _mm_add_pi32(self.state, _mm_set_pi32(0, 1)) };
        // let m3 = unsafe { _mm_set_epi64(_mm_setzero_si64(), self.state) };
        // self.state = unsafe { _mm_add_pi32(self.state, _mm_set_pi32(0, 1)) };
        // let c = self.aes.encrypt4(Block512::from([m0, m1, m2, m3]));
        // *results = c.into();
    }
    #[inline]
    #[cfg(not(feature = "nightly"))]
    fn generate(&mut self, results: &mut Self::Results) {
        let m0 = Block::from(u128::from(self.state));
        self.state += 1;
        *results = self.aes.encrypt(m0).into();
        // let m0 = Block::from(self.state as u128);
        // self.state += 1;
        // let m1 = Block::from(self.state as u128);
        // self.state += 1;
        // let m2 = Block::from(self.state as u128);
        // self.state += 1;
        // let m3 = Block::from(self.state as u128);
        // self.state += 1;
        // let c = self.aes.encrypt4(Block512::from([m0, m1, m2, m3]));
        // *results = c.into();
    }
}

impl SeedableRng for AesRngCore {
    type Seed = Block;

    #[inline]
    #[cfg(feature = "nightly")]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = Aes128::new(seed);
        AesRngCore {
            aes,
            state: unsafe { _mm_setzero_si64() },
        }
    }
    #[inline]
    #[cfg(not(feature = "nightly"))]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = Aes128::new(seed);
        AesRngCore { aes, state: 0u64 }
    }
}

impl CryptoRng for AesRngCore {}

impl From<AesRngCore> for AesRng {
    #[inline]
    fn from(core: AesRngCore) -> Self {
        AesRng(BlockRng::new(core))
    }
}
