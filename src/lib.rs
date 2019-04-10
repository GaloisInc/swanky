// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `twopac` implements (semi-honest) garbled-circuit-based two-party secure
//! computation in rust, using `ocelot` for oblivious transfer and
//! `fancy-garbling` for garbled circuits.
//!
//! **THIS IS VERY MUCH RESEARCH CODE!** (for now)

#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

mod comm;
mod errors;

pub use errors::Error;
pub mod semihonest;
