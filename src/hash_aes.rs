// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementations of correlation-robust hash functions (and their variants)
//! based on fixed-key AES.

use crate::{Aes128, Block, FIXED_KEY_AES128};
use core::arch::x86_64::*;

/// AES-based correlation-robust hash function.
///
/// This hash function supports the correlation-robust variants given in
/// <https://eprint.iacr.org/2019/074>.
pub struct AesHash {
    aes: Aes128,
}

/// `AesHash` with a fixed key.
pub const AES_HASH: AesHash = AesHash {
    aes: FIXED_KEY_AES128,
};

impl AesHash {
    /// Initialize the hash function using `key`.
    #[inline]
    pub fn new(key: Block) -> Self {
        let aes = Aes128::new(key);
        AesHash { aes }
    }

    /// Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// The function computes `π(x) ⊕ x`.
    #[inline]
    pub fn cr_hash(&self, _i: Block, x: Block) -> Block {
        self.aes.encrypt(x) ^ x
    }

    /// Circular correlation-robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `H(σ(x))`, where `H` is a correlation-robust hash
    /// function and `σ(x₀ || x₁) = (x₀ ⊕ x₁) || x₁`.
    #[inline]
    pub fn ccr_hash(&self, i: Block, x: Block) -> Block {
        unsafe {
            let x = _mm_xor_si128(
                _mm_shuffle_epi32(x.into(), 78),
                #[allow(overflowing_literals)]
                _mm_and_si128(x.into(), _mm_set_epi64x(0xFFFF_FFFF_FFFF_FFFF, 0x00)),
            );
            self.cr_hash(i, Block::from(x))
        }
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `π(π(x) ⊕ i) ⊕ π(x)`.
    #[inline]
    pub fn tccr_hash(&self, i: Block, x: Block) -> Block {
        let y = self.aes.encrypt(x);
        let t = y ^ i;
        let z = self.aes.encrypt(t);
        y ^ z
    }
}
