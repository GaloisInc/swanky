// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang random subfield VOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>).

mod base_svole;
mod copee;
mod ggm_utils;
mod spsvole;
mod svole;
mod utils;

pub use svole::{Receiver, Sender};
