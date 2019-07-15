// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

//!

mod errors;

pub use errors::Error;
pub mod semihonest;
