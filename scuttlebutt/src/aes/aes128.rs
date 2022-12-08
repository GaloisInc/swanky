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

use std::convert::TryInto;

use crate::Block;
use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128 as AesAes128;

/// AES-128, encryption only.
#[derive(Clone)]
pub struct Aes128 {
    rkeys: AesAes128,
}

impl Aes128 {
    /// Create a new `Aes128` object, using `key` as the AES key.
    #[inline]
    pub fn new(key: Block) -> Self {
        let key_bytes: [u8; 16] = key.as_ref().try_into().unwrap();
        let key = GenericArray::from(key_bytes);
        let rkeys: AesAes128 = AesAes128::new(&key);
        Self { rkeys: rkeys }
    }

    /// Encrypt a block, outputting the ciphertext.
    #[inline(always)]
    pub fn encrypt(&self, m: Block) -> Block {
        let rkeys = self.rkeys;
        let m_bytes: [u8; 16] = m.as_ref().try_into().unwrap();
        let in_place = m_bytes.try_into().unwrap();
        rkeys.encrypt_block(&mut in_place);
        Block(in_place)
    }

    /// Encrypt eight blocks at a time, outputting the ciphertexts.
    #[inline(always)]
    pub fn encrypt8(&self, mut blocks: [Block; 8]) -> [Block; 8] {
        let rkeys = self.rkeys;
        let mut blocks_copy = blocks.to_vec();
        rkeys.encrypt_blocks(&mut blocks_copy);
        blocks_copy.into()
    }
}

union __U128 {
    #[cfg(target_feature = "sse2")]
    vector: __m128i,
    #[cfg(not(target_feature = "sse2"))]
    vector: u128,
    bytes: u128,
}

/// Fixed-key AES-128.
pub const FIXED_KEY_AES128: Aes128 = Aes128 {
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
