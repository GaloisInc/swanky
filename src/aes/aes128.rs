// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

// Portions of the below code adapted from the `aesni` crate (version 0.6.0),
// which uses the following license:
//
// Copyright (c) 2017 Artyom Pavlov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::{Block, Block512};
use std::arch::x86_64::*;

/// AES-128, encryption only.
#[derive(Clone)]
pub struct Aes128 {
    rkeys: [__m128i; 11],
}

impl Aes128 {
    /// Create a new `Aes128` object, using `key` as the AES key.
    #[inline]
    pub fn new(key: Block) -> Self {
        let rkeys = expand(key.0);
        Aes128 { rkeys }
    }
    /// Encrypt a block, outputting the ciphertext.
    #[inline]
    pub fn encrypt(&self, m: Block) -> Block {
        let keys = self.rkeys;
        unsafe {
            let mut c: __m128i;
            c = _mm_xor_si128(m.0, keys[0]);
            c = _mm_aesenc_si128(c, keys[1]);
            c = _mm_aesenc_si128(c, keys[2]);
            c = _mm_aesenc_si128(c, keys[3]);
            c = _mm_aesenc_si128(c, keys[4]);
            c = _mm_aesenc_si128(c, keys[5]);
            c = _mm_aesenc_si128(c, keys[6]);
            c = _mm_aesenc_si128(c, keys[7]);
            c = _mm_aesenc_si128(c, keys[8]);
            c = _mm_aesenc_si128(c, keys[9]);
            Block(_mm_aesenclast_si128(c, keys[10]))
        }
    }
    /// Encrypt four blocks at a time, outputting the ciphertexts.
    #[inline]
    pub fn encrypt4(&self, m: Block512) -> Block512 {
        let keys = self.rkeys;
        let mut c: [__m128i; 4] = m.into();
        unsafe {
            c[0] = _mm_xor_si128(c[0], keys[0]);
            c[1] = _mm_xor_si128(c[1], keys[0]);
            c[2] = _mm_xor_si128(c[2], keys[0]);
            c[3] = _mm_xor_si128(c[3], keys[0]);
            c[0] = _mm_aesenc_si128(c[0], keys[1]);
            c[1] = _mm_aesenc_si128(c[1], keys[1]);
            c[2] = _mm_aesenc_si128(c[2], keys[1]);
            c[3] = _mm_aesenc_si128(c[3], keys[1]);
            c[0] = _mm_aesenc_si128(c[0], keys[2]);
            c[1] = _mm_aesenc_si128(c[1], keys[2]);
            c[2] = _mm_aesenc_si128(c[2], keys[2]);
            c[3] = _mm_aesenc_si128(c[3], keys[2]);
            c[0] = _mm_aesenc_si128(c[0], keys[3]);
            c[1] = _mm_aesenc_si128(c[1], keys[3]);
            c[2] = _mm_aesenc_si128(c[2], keys[3]);
            c[3] = _mm_aesenc_si128(c[3], keys[3]);
            c[0] = _mm_aesenc_si128(c[0], keys[4]);
            c[1] = _mm_aesenc_si128(c[1], keys[4]);
            c[2] = _mm_aesenc_si128(c[2], keys[4]);
            c[3] = _mm_aesenc_si128(c[3], keys[4]);
            c[0] = _mm_aesenc_si128(c[0], keys[5]);
            c[1] = _mm_aesenc_si128(c[1], keys[5]);
            c[2] = _mm_aesenc_si128(c[2], keys[5]);
            c[3] = _mm_aesenc_si128(c[3], keys[5]);
            c[0] = _mm_aesenc_si128(c[0], keys[6]);
            c[1] = _mm_aesenc_si128(c[1], keys[6]);
            c[2] = _mm_aesenc_si128(c[2], keys[6]);
            c[3] = _mm_aesenc_si128(c[3], keys[6]);
            c[0] = _mm_aesenc_si128(c[0], keys[7]);
            c[1] = _mm_aesenc_si128(c[1], keys[7]);
            c[2] = _mm_aesenc_si128(c[2], keys[7]);
            c[3] = _mm_aesenc_si128(c[3], keys[7]);
            c[0] = _mm_aesenc_si128(c[0], keys[8]);
            c[1] = _mm_aesenc_si128(c[1], keys[8]);
            c[2] = _mm_aesenc_si128(c[2], keys[8]);
            c[3] = _mm_aesenc_si128(c[3], keys[8]);
            c[0] = _mm_aesenc_si128(c[0], keys[9]);
            c[1] = _mm_aesenc_si128(c[1], keys[9]);
            c[2] = _mm_aesenc_si128(c[2], keys[9]);
            c[3] = _mm_aesenc_si128(c[3], keys[9]);
            c[0] = _mm_aesenclast_si128(c[0], keys[10]);
            c[1] = _mm_aesenclast_si128(c[1], keys[10]);
            c[2] = _mm_aesenclast_si128(c[2], keys[10]);
            c[3] = _mm_aesenclast_si128(c[3], keys[10]);
            Block512::from(c)
        }
    }
}

macro_rules! expand_round {
    ($enc_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t2;
        let mut t3;

        t2 = _mm_aeskeygenassist_si128(t1, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t3 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);
    };
}

#[inline(always)]
fn expand(key: __m128i) -> [__m128i; 11] {
    unsafe {
        let mut keys: [__m128i; 11] = std::mem::uninitialized();
        _mm_store_si128(keys.as_mut_ptr(), key);
        expand_round!(keys, 1, 0x01);
        expand_round!(keys, 2, 0x02);
        expand_round!(keys, 3, 0x04);
        expand_round!(keys, 4, 0x08);
        expand_round!(keys, 5, 0x10);
        expand_round!(keys, 6, 0x20);
        expand_round!(keys, 7, 0x40);
        expand_round!(keys, 8, 0x80);
        expand_round!(keys, 9, 0x1B);
        expand_round!(keys, 10, 0x36);
        keys
    }
}

union __U128 {
    vector: __m128i,
    bytes: u128,
}

/// Fixed-key AES-128.
#[deprecated(note = "use `FIXED_KEY_AES128` instead")]
pub const AES: Aes128 = Aes128 {
    rkeys: unsafe {
        [
            (__U128 {
                bytes: 0x15B5_32C2_F193_1C94,
            })
            .vector,
            (__U128 {
                bytes: 0xD754_876D_FE7E_6726,
            })
            .vector,
            (__U128 {
                bytes: 0xA7EB_4F98_1986_CFCF,
            })
            .vector,
            (__U128 {
                bytes: 0x80E6_BBED_F88D_E8C9,
            })
            .vector,
            (__U128 {
                bytes: 0x1210_4B44_43D8_B35C,
            })
            .vector,
            (__U128 {
                bytes: 0xF467_7B3C_8DCB_047B,
            })
            .vector,
            (__U128 {
                bytes: 0x578C_DBAC_AED1_C9DC,
            })
            .vector,
            (__U128 {
                bytes: 0x295D_2051_CF6F_5E25,
            })
            .vector,
            (__U128 {
                bytes: 0x0CE1_FD36_50DE_FFAB,
            })
            .vector,
            (__U128 {
                bytes: 0xDDFA_4FE9_E2CD_2D23,
            })
            .vector,
            (__U128 {
                bytes: 0x96F6_769D_AF14_18D2,
            })
            .vector,
        ]
    },
};

/// AES-128 with a fixed key.
#[allow(deprecated)]
pub const FIXED_KEY_AES128: Aes128 = AES;

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes_128() {
        let key = Block::from(0x3C4FCF098815F7ABA6D2AE2816157E2B);
        let pt = Block::from(0x2A179373117E3DE9969F402EE2BEC16B);
        let cipher = Aes128::new(key);
        let ct = cipher.encrypt(pt);
        assert_eq!(ct, Block::from(0x97EF6624F3CA9EA860367A0DB47BD73A));
    }
}
