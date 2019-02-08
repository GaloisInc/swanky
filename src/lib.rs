// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `ocelot` is an oblivious transfer (+ extension) library written in rust.
//! Currently it only implements semi-honest constructions.
//!
//! `ocelot` attempts to use all the latest-and-greatest optimizations, including:
//! * Fixed-key AES wherever possible (cf. <https://eprint.iacr.org/2019/074>)
//! * An assembly implementation of matrix transposition from the EMP toolkit's OT implementation (cf. <https://github.com/emp-toolkit/emp-ot>)
//!
//! Even with these optimizations, we are currently far from the performance of
//! other libraries, such as the EMP toolkit. Hopefully someday we'll get there!
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

pub use crate::block::*;
pub use crate::hash_aes::AesHash;
pub use crate::ot::*;
pub use crate::rand_aes::AesRng;
