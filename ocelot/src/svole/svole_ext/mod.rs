// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides traits COPEe

mod sp_svole;

use crate::errors::Error;
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A type for security parameters
pub struct Params;

impl Params {
    /// The exponent in the input vector length `n = 2^h`.
    pub const H: usize = 3;
    /// The input vector length `n = 2^h`.
    pub const N: usize = 2 ^ (Params::H);
}

/// A trait for SpsVole Sender.
pub trait SpsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    /// Runs single-point svole and outputs pair of vectors `(u, w)` such that
    /// the correlation $w = u\Delta+v$ holds.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<(Vec<<Self::Msg as FF>::PrimeField>, Vec<Self::Msg>), Error>;
}

/// A trait for SpsVole Sender.
pub trait SpsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    /// Runs single-point svole and outputs a vector `v` such that
    /// the correlation $w = u\Delta+v$ holds.
    fn get_delta(&self) -> Self::Msg;
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<Option<Vec<Self::Msg>>, Error>;
}
