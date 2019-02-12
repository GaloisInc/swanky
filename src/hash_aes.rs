// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementations of correlation-robust hash functions (and their variants)
//! based on fixed-key AES.

use crate::aes::Aes128;
use crate::Block;
use core::arch::x86_64::*;

/// AES-based correlation-robust hash function.
pub struct AesHash {
    aes: Aes128,
}

impl AesHash {
    #[inline(always)]
    pub fn new(key: &Block) -> Self {
        let aes = Aes128::new(key);
        AesHash { aes }
    }

    /// Correlation robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// The function computes `π(x) ⊕ x`.
    #[inline(always)]
    pub fn cr_hash(&self, _i: usize, x: Block) -> Block {
        self.aes.encrypt_u8(&x) ^ x
    }

    /// Circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `H(σ(x))`, where `H` is a correlation robust hash
    /// function and `σ(x₀ || x₁) = (x₀ ⊕ x₁) || x₁`.
    #[inline(always)]
    pub fn ccr_hash(&self, _i: usize, x: Block) -> Block {
        unsafe {
            let x = _mm_xor_si128(
                _mm_shuffle_epi32(x.into(), 78),
                _mm_and_si128(
                    x.into(),
                    _mm_set_epi64(_mm_set1_pi8(0xF), _mm_setzero_si64()),
                ),
            );
            let x = Block::from(x);
            let y = self.aes.encrypt_u8(&x);
            x ^ y
        }
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `π(π(x) ⊕ i) ⊕ π(x)`.
    #[inline(always)]
    pub fn tccr_hash(&self, i: usize, x: Block) -> Block {
        unsafe {
            let y = self.aes.encrypt_u8(&x);
            let i = _mm_set_epi64(_mm_setzero_si64(), std::mem::transmute::<usize, __m64>(i));
            let t = _mm_xor_si128(y.into(), i);
            let z = self.aes.encrypt_u8(&Block::from(t));
            y ^ z
        }
    }
}

#[cfg(test)]
mod benchmarks {
    extern crate test;

    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_cr_hash(b: &mut Bencher) {
        let hash = AesHash::new(&rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.cr_hash(i, x));
    }

    #[bench]
    fn bench_ccr_hash(b: &mut Bencher) {
        let hash = AesHash::new(&rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.ccr_hash(i, x));
    }

    #[bench]
    fn bench_tccr_hash(b: &mut Bencher) {
        let hash = AesHash::new(&rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.tccr_hash(i, x));
    }

}
