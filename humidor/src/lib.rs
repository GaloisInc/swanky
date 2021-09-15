// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! Humidor is an implementation of the Ligero ZK protocol:
//! https://dl.acm.org/doi/pdf/10.1145/3133956.3134104

#![deny(missing_docs)]

mod util;
pub mod merkle;
pub mod params;
pub mod ligero;
pub mod circuit;
