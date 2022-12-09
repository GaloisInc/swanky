// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementations of correlation-robust hash functions (and their variants)
//! based on fixed-key AES.

use crate::{Aes128, Block};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// AES-based correlation-robust hash function.
///
/// This hash function supports the correlation-robust variants given in
/// <https://eprint.iacr.org/2019/074>.
pub struct AesHash {
    aes: Aes128,
}

/// Fixed-key AES-128.
// TODO(interstellar) what are those values?? do they really matter?
// cf paper(pdf) linked in previous versions
// const FIXED_KEY_AES128: &[u128; 11] = &[
//     0x15B5_32C2_F193_1C94,
//     0xD754_876D_FE7E_6726,
//     0xA7EB_4F98_1986_CFCF,
//     0x80E6_BBED_F88D_E8C9,
//     0x1210_4B44_43D8_B35C,
//     0xF467_7B3C_8DCB_047B,
//     0x578C_DBAC_AED1_C9DC,
//     0x295D_2051_CF6F_5E25,
//     0x0CE1_FD36_50DE_FFAB,
//     0xDDFA_4FE9_E2CD_2D23,
//     0x96F6_769D_AF14_18D2,
// ];
const FIXED_KEY_AES128: [u8; 16] = [
    0x15, 0x26, 0xCF, 0xE8, 0x5C, 0xB3, 0xDC, 0x51, 0x1F, 0xDD, 0xF2, 0xCF, 0xD3, 0x98, 0xA3, 0x6F,
];

impl AesHash {
    /// Initialize the hash function using `key`.
    #[inline]
    pub fn new(key: Block) -> Self {
        let aes = Aes128::new(key);
        AesHash { aes }
    }

    /// `AesHash` with a fixed key.
    #[inline]
    pub fn new_with_fixed_key() -> Self {
        let aes = Aes128::new(FIXED_KEY_AES128.into());
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
    #[cfg(target_arch = "x86_64")]
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
    // TODO(interstellar) add overload "inplace"
    #[inline]
    pub fn tccr_hash(&self, i: Block, x: Block) -> Block {
        let y = self.aes.encrypt(x);
        let t = y ^ i;
        let z = self.aes.encrypt(t);
        y ^ z
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use core::arch::x86_64::__m128i;

    #[test]
    fn test_two_instances_return_same_tccr_hash() {
        let hash1 = AesHash::new_with_fixed_key();
        let hash2 = AesHash::new_with_fixed_key();

        let inputs = unsafe {
            [(
                Block(_mm_set_epi32(1, 2, 3, 4)),
                Block(_mm_set_epi32(5, 6, 7, 8)),
            )]
        };

        for (block, tweak) in inputs {
            assert_eq!(hash1.tccr_hash(block, tweak), hash2.tccr_hash(block, tweak));
        }
    }

    #[test]
    fn test_tccr_hash_stable() {
        let hash = AesHash::new_with_fixed_key();

        let input = unsafe { Block(_mm_set_epi32(1, 2, 3, 4)) };
        let tweak = unsafe { Block(_mm_set_epi32(5, 6, 7, 8)) };

        let res1 = hash.tccr_hash(input, tweak);

        assert_eq!(hash.tccr_hash(input, tweak), res1);
    }
}
