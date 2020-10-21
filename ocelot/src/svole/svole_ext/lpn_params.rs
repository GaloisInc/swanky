// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Secure LPN parameters presented in (cf.
//! <https://eprint.iacr.org/2020/925>, Table 2).

/// LPN parameters for setup phase.
pub struct LpnSetupParams;

impl LpnSetupParams {
    /// Exponant which represent the depth of the GGM tree.
    pub const EXP: usize = 8;
    /// Hamming weight of the error vector `e` used in LPN assumption.
    pub const WEIGHT: usize = 2508;
    /// Number of columns `n` in the LPN matrix.
    pub const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 642048
    /// Number of rows `k` in the LPN matrix.
    pub const ROWS: usize = 19870;
    /// Small constant `d` used in the `liner codes` useful in acheiving efficient matrix multiplication.
    pub const D: usize = 10;
}

/// LPN parameters for extend phase.
pub struct LpnExtendParams;

impl LpnExtendParams {
    /// Exponant which represent the depth of the GGM tree.
    pub const EXP: usize = 13;
    /// Hamming weight of the error vector `e` used in LPN assumption.
    pub const WEIGHT: usize = 1319;
    /// Number of columns `n` in the LPN matrix.
    pub const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 10,805,248
    /// Number of rows `k` in the LPN matrix.
    pub const ROWS: usize = 589_760;
    /// Small constant `d` used in the `liner codes` useful in acheiving efficient matrix multiplication.
    pub const D: usize = 10;
}
