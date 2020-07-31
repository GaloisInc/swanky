// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Puncturable PRF (PPRF) Traits
//!
//! This module provides traits for Puncturable Pseudo-Random Functions

pub mod distr_pprf;
pub mod pprf;

use crate::field::Fp;
use crate::pprf::pprf::{Fp2, Pprf as PprfTrait};
#[allow(unused_imports)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use scuttlebutt::{AbstractChannel, Block};

/// A trait for PPRF Sender.
pub trait PprfSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init() -> Result<Self, Error>;
    fn send<C: AbstractChannel, PPRF: PprfTrait>(
        &mut self,
        channel: &mut C,
        bpprf: &mut PPRF,
        beta: (Fp, Fp),
    ) -> Result<Block, Error>;
}

/// A trait for PPRF Receiver
pub trait PprfReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init() -> Result<Self, Error>;

    fn receive<C: AbstractChannel, PPRF: PprfTrait>(
        &mut self,
        channel: &mut C,
        bpprf: &mut PPRF,
        alpha: Block,
    ) -> Option<(Vec<Block>, (Fp, Fp))>;
}

/// convert bool vector to u128
pub fn vec_bool_u128(x: Vec<bool>) -> u128 {
    let res: u128 = (0..(x.len())).fold(0, |sum, i| sum + (2 ^ (i as u128)) * (u128::from(x[i])));
    res
}
