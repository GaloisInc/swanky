// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

//!

mod cuckoo;
mod errors;
mod psi;
pub mod utils;

pub use crate::{errors::Error, psi::*};
