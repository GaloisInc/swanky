// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! The following modules implement the protocols presented in the paper (<https://eprint.iacr.org/2020/925.pdf>).
/// COPEe protocol presented in Figure 13.
pub mod base_svole;
/// COPEe protocol presented in Figure 12.
pub mod copee;
/// Implementation of Single-Point sVOLE and sVOLE extension protocols presented in Section 5.1 and 5.2 respectively.
pub mod svole_ext;
/// Auxiliary functions.
pub mod utils;
