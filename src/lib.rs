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
//! We use a computation security parameter of `κ = 128` throughout in order to
//! benefit from SIMD operations over 128-bit values.
//!
//! **THIS IS STILL VERY MUCH RESEARCH CODE**, for now.

#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(asm))]

mod cointoss;
mod stream;
mod utils;

mod errors;
pub use crate::errors::Error;

mod ot;
pub use crate::ot::*;
mod oprf;
pub use crate::oprf::*;
