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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tstd as std;

use std::convert::TryInto;

use crate::Block;
use aes::cipher::{generic_array::typenum, generic_array::GenericArray, BlockEncrypt, KeyInit};
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
        let key = GenericArray::from_slice(key.as_ref());
        // expand_key();
        let rkeys: AesAes128 = AesAes128::new(&key);
        Self { rkeys: rkeys }
    }

    /// Encrypt a block, outputting the ciphertext.
    #[inline(always)]
    pub fn encrypt(&self, m: Block) -> Block {
        let rkeys: &AesAes128 = &self.rkeys;
        // let m_bytes: [u8; 16] = m.as_ref().try_into().unwrap();
        // let mut in_place = m_bytes.try_into().unwrap();
        let mut in_place: GenericArray<u8, typenum::U16> =
            GenericArray::clone_from_slice(m.as_ref());
        rkeys.encrypt_block(&mut in_place);
        // in_place.as_slice().into()

        let in_place: [u8; 16] = in_place.as_slice().try_into().expect("Wrong length");
        in_place.into()
    }

    /// Encrypt a block, outputting the ciphertext.
    /// in-place version
    #[inline(always)]
    pub fn encrypt_inplace(&self, block: &mut Block) {
        let rkeys: &AesAes128 = &self.rkeys;
        let in_place: &mut GenericArray<u8, typenum::U16> =
            GenericArray::from_mut_slice(block.as_mut());
        rkeys.encrypt_block(in_place);
    }

    /// Encrypt eight blocks at a time, outputting the ciphertexts.
    #[cfg(feature = "rand_aes")]
    #[inline(always)]
    pub fn encrypt8(&self, blocks: [Block; 8]) -> [Block; 8] {
        // let rkeys: &AesAes128 = &self.rkeys;
        // TODO(interstellar)!!! use "encrypt_blocks"
        // let mut blocks_copy: [GenericArray<u8, typenum::U8>] = blocks
        //     .iter()
        //     .map(|m| {
        //         let m_bytes: [u8; 8] = m.as_ref().try_into().unwrap();
        //         m_bytes
        //     })
        //     .collect();
        // let mut blocks_copy = GenericArray::from(blocks);
        // let mut blocks_copy: [GenericArray<u8, typenum::U8>] = blocks_copy
        //     .iter()
        //     .map(|m| {
        //         let m_bytes: [u8; 8] = m.as_ref().try_into().unwrap();
        //         m_bytes
        //     })
        //     .collect();
        // rkeys.encrypt_blocks(&mut blocks_copy);
        // blocks_copy.into()
        [
            self.encrypt(blocks[0]),
            self.encrypt(blocks[1]),
            self.encrypt(blocks[2]),
            self.encrypt(blocks[3]),
            self.encrypt(blocks[4]),
            self.encrypt(blocks[5]),
            self.encrypt(blocks[6]),
            self.encrypt(blocks[7]),
        ]
    }
}

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
