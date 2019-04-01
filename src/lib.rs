// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `ocelot` is an oblivious transfer (+ extension) library written in rust.
//!
//! `ocelot` supports all the latest-and-greatest OT-esque protocols, including
//! efficient base OT and semi-honest + malicious OT extension. `ocelot` also
//! provides oblivious PRF support.

#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(asm))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

mod stream;
mod utils;

mod errors;
pub use crate::errors::Error;

#[cfg(feature = "unstable")]
pub mod oprf;
pub mod ot;
