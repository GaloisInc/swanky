// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![feature(stdsimd)]
#![feature(test)]

mod aes;
mod block;
mod hash_aes;
mod rand_aes;

pub use crate::block::Block;
pub use crate::hash_aes::AesHash;
pub use crate::rand_aes::AesRng;
