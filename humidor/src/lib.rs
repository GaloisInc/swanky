// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! Humidor is an implementation of the Ligero ZK protocol:
//! https://dl.acm.org/doi/pdf/10.1145/3133956.3134104

#![feature(is_sorted)]
#![deny(missing_docs)]

pub mod circuit;
pub mod ligero;
pub mod merkle;
pub mod params;
mod util;
