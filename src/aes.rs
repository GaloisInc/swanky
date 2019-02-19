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

//! Implementation of AES-128 (encryption only!) using Intel's AES-NI.

use crate::Block;
use core::arch::x86_64::*;
use core::mem;

#[derive(Clone)]
pub struct Aes128 {
    rkeys: [__m128i; 11],
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

#[inline]
fn expand(key: __m128i) -> [__m128i; 11] {
    unsafe {
        let mut keys: [__m128i; 11] = mem::uninitialized();
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

impl Aes128 {
    #[inline]
    pub fn new(key: Block) -> Self {
        let rkeys = expand(key.0);
        Aes128 { rkeys }
    }

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
}

#[cfg(test)]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_aes_new(b: &mut Bencher) {
        let key = rand::random::<Block>();
        b.iter(|| Aes128::new(key));
    }

    #[bench]
    fn bench_aes_encrypt(b: &mut Bencher) {
        let aes = Aes128::new(rand::random::<Block>());
        let block = Block::zero();
        b.iter(|| aes.encrypt(block));
    }
}
