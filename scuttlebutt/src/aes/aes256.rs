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
// use core::{arch::x86_64::*, mem};
use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256 as AesAes256;
use std::convert::TryInto;

/// AES-256, encryption only.
#[derive(Clone)]
pub struct Aes256 {
    rkeys: AesAes256,
}

impl Aes256 {
    /// Make a new `Aes256` object with key `key`.
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        let key = GenericArray::from(key);
        let rkeys: AesAes256 = AesAes256::new(&key);
        Self { rkeys: rkeys }
    }

    /// Encrypt block `m`.
    #[inline]
    pub fn encrypt(&self, m: Block) -> Block {
        let rkeys = self.rkeys;
        let m_bytes: [u8; 16] = m.as_ref().try_into().unwrap();
        let in_place = m_bytes.try_into().unwrap();
        rkeys.encrypt_block(&mut in_place);
        Block(in_place)
    }
}
