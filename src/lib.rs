// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `popsicle` is a private set intersection (PSI) library written in rust.
//!
//! `popsicle` exposes PSI through two traits: `PrivateSetIntersectionSender`
//! and `PrivateSetIntersectionReceiver`. Each trait has an `init` function
//! which runs any one-time initialization, and a `send` / `receive` function,
//! which computes the set intersection.
//!
//! `popsicle` currently supports the following instantiations of the PSI traits:
//!
//! * The Pinkas-Schneider-Zohner PSI protocol (cf.
//! <https://eprint.iacr.org/2014/447>), including optimizations as specified by
//! Kolesnikov-Kumaresan-Rosulek-Trieu (cf. <https://eprint.iacr.org/2016/799>).
//!
//! **THIS IS STILL VERY MUCH RESEARCH CODE**, for now.

#![cfg_attr(feature = "nightly", feature(test))]

mod cuckoo;
mod errors;
mod psi;
mod stream;
mod utils;

pub use crate::errors::Error;
pub use crate::psi::*;
