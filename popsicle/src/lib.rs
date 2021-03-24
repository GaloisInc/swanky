// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.
#![cfg_attr(feature = "nightly", feature(test))]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

//!

mod cuckoo;
mod errors;
mod psi;
mod utils;

pub use crate::{errors::Error, psi::*};
