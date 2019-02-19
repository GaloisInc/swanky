// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `ocelot` is an oblivious transfer (+ extension) library written in rust.
//!
//! `ocelot` exposes oblivious transfer (OT) through two traits:
//! `ObliviousTransferSender` and `ObliviousTransferReceiver`. Each trait has an
//! `init` function, which runs any one-time initialization (e.g., for OT
//! extension this corresponds to the running of the base OTs). The traits then
//! have either a `send` or `receive` method, which runs the OT sender or
//! receiver, respectively. This method can be run multiple times, allowing one
//! to for example run OT extension multiple times without having to re-do the
//! initialization phase.
//!
//! `ocelot` also supports correlated OT and random OT through the
//! `CorrelatedObliviousTransferSender/Receiver` and
//! `RandomObliviousTransferSender/Receiver` traits.
//!
//! `ocelot` attempts to use all the latest-and-greatest optimizations, including:
//! * Fixed-key AES wherever possible (cf. <https://eprint.iacr.org/2019/074>).
//! * An optimized implementation of matrix transposition from the EMP toolkit's OT implementation (cf. <https://github.com/emp-toolkit/emp-ot>).
//!
//! **THIS IS STILL VERY MUCH RESEARCH CODE**, for now.

#![allow(clippy::many_single_char_names)]
#![feature(non_ascii_idents)]
#![feature(test)]
#![feature(stdsimd)]
#![feature(asm)]

mod aes;
mod block;
mod cointoss;
mod hash_aes;
mod ot;
mod rand_aes;
mod stream;
mod utils;

pub use crate::block::Block;
pub use crate::hash_aes::AesHash;
pub use crate::ot::*;
pub use crate::rand_aes::AesRng;
