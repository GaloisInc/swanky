// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

mod sp_svole;
//mod svole_lpn;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A trait for SpsVole Sender.
pub trait SpsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs single-point svole and outputs pair of vectors `(u, w)` such that
    /// the correlation $w = u\Delta+v$ holds.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        exp_h: usize,
    ) -> Result<(Vec<<Self::Msg as FF>::PrimeField>, Vec<Self::Msg>), Error>;
}

/// A trait for SpsVole Receiver.
pub trait SpsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// Runs single-point svole and outputs a vector `v` such that
    /// the correlation $w = u\Delta+v$ holds.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        exp_h: usize,
    ) -> Result<Option<Vec<Self::Msg>>, Error>;
}

/// LPN based sVole.
pub struct LpnParams;

impl LpnParams {
    pub const N: usize = 10;
    pub const K: usize = 5;
    pub const T: usize = 3;
    pub const L: usize = Self::N - Self::K;
    pub const M: usize = Self::N / Self::T;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// This procedure can be run multiple times and produces `L` sVole correlations,
    /// i.e, outputs `u` and `w` such that $w = u\Delta+v$, each iteration.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<<Self::Msg as FF>::PrimeField>, Vec<Self::Msg>), Error>;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// This procedure can be run multiple times and produces `L` sVole correlations,
    /// i.e, outputs `v` such that $w = u\Delta+v$, each iteration.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Option<Vec<Self::Msg>>, Error>;
}
