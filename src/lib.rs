// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `ocelot` is an oblivious transfer (+ extension) library written in rust.
//!
//! `ocelot` attempts to use all the latest-and-greatest optimizations, including:
//! * Fixed-key AES wherever possible (cf. <https://eprint.iacr.org/2019/074>)
//! * An assembly implementation of matrix transposition from the EMP toolkit's OT implementation (cf. <https://github.com/emp-toolkit/emp-ot>)
//!
//! **THIS IS VERY MUCH RESEARCH CODE!** (for now)

#![feature(non_ascii_idents)]
#![feature(test)]
#![feature(stdsimd)]
#![feature(asm)]

mod aes;
mod block;
mod hash_aes;
mod ot;
mod rand_aes;
mod stream;
mod utils;

pub use crate::block::Block;
pub use crate::hash_aes::AesHash;
pub use crate::ot::*;
pub use crate::rand_aes::AesRng;
