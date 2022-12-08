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

use crate::Block;
use core::{arch::x86_64::*, mem};

/// AES-256, encryption only.
#[derive(Clone)]
pub struct Aes256 {
    rkeys: [__m128i; 15],
}

macro_rules! expand_round {
    ($enc_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 2));
        let mut t2;
        let mut t3 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);

        t4 = _mm_aeskeygenassist_si128(t1, 0x00);
        t2 = _mm_shuffle_epi32(t4, 0xaa);
        t4 = _mm_slli_si128(t3, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t3 = _mm_xor_si128(t3, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos + 1), t3);
    };
}

macro_rules! expand_round_last {
    ($enc_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 2));
        let mut t2;
        let t3 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);
    };
}

#[inline(always)]
fn expand(key: &[u8; 32]) -> [__m128i; 15] {
    unsafe {
        let mut enc_keys: [__m128i; 15] = mem::MaybeUninit::uninit().assume_init();

        #[allow(clippy::useless_transmute)] // XXX remove if possible!
        let kp = std::mem::transmute(key);
        // let kp = key.as_ptr() as *const __m128i;
        let k1 = _mm_loadu_si128(kp);
        let k2 = _mm_loadu_si128(kp.offset(1));
        _mm_store_si128(enc_keys.as_mut_ptr(), k1);
        _mm_store_si128(enc_keys.as_mut_ptr().offset(1), k2);

        expand_round!(enc_keys, 2, 0x01);
        expand_round!(enc_keys, 4, 0x02);
        expand_round!(enc_keys, 6, 0x04);
        expand_round!(enc_keys, 8, 0x08);
        expand_round!(enc_keys, 10, 0x10);
        expand_round!(enc_keys, 12, 0x20);
        expand_round_last!(enc_keys, 14, 0x40);

        enc_keys
    }
}

impl Aes256 {
    /// Make a new `Aes256` object with key `key`.
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        let rkeys = expand(key);
        Self { rkeys }
    }
    /// Encrypt block `m`.
    #[inline]
    pub fn encrypt(&self, m: Block) -> Block {
        let keys = self.rkeys;
        unsafe {
            let mut block = m.0;
            block = _mm_xor_si128(block, keys[0]);
            block = _mm_aesenc_si128(block, keys[1]);
            block = _mm_aesenc_si128(block, keys[2]);
            block = _mm_aesenc_si128(block, keys[3]);
            block = _mm_aesenc_si128(block, keys[4]);
            block = _mm_aesenc_si128(block, keys[5]);
            block = _mm_aesenc_si128(block, keys[6]);
            block = _mm_aesenc_si128(block, keys[7]);
            block = _mm_aesenc_si128(block, keys[8]);
            block = _mm_aesenc_si128(block, keys[9]);
            block = _mm_aesenc_si128(block, keys[10]);
            block = _mm_aesenc_si128(block, keys[11]);
            block = _mm_aesenc_si128(block, keys[12]);
            block = _mm_aesenc_si128(block, keys[13]);
            Block(_mm_aesenclast_si128(block, keys[14]))
        }
    }
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes_256() {
        let k1: u128 = 0x81777D85F0AE732BBE71CA1510EB3D60;
        let k2: u128 = 0xF4DF1409A310982DD708613B072C351F;
        let key = [k1, k2];
        let key = unsafe { std::mem::transmute(key) };
        let cipher = Aes256::new(&key);
        let pt = Block::from(0x2A179373117E3DE9969F402EE2BEC16B);
        let ct = cipher.encrypt(pt);
        assert_eq!(ct, Block::from(0xF881B13D7E5A4B063CA0D2B5BDD1EEF3));
    }
}
