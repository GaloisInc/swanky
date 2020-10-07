// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Secure LPN parameters presented in Xiao's paper (latest draft)

pub struct LpnSetupParams;

impl LpnSetupParams {
    pub const EXP: usize = 8;
    pub const WEIGHT: usize = 2508;
    pub const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 642048
    pub const ROWS: usize = 19870;
    pub const D: usize = 10;
}

pub struct LpnExtendParams;

impl LpnExtendParams {
    pub const EXP: usize = 13;
    pub const WEIGHT: usize = 1319;
    pub const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 10,805,248
    pub const ROWS: usize = 589760;
    pub const D: usize = 10;
}
