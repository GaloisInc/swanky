// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licfensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

mod ggm_utils;
pub mod sp_svole;
pub mod svole_lpn;

use crate::errors::Error;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A trait for LpnsVole Sender.
pub trait LpnsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization with secure LPN parameters, k (rows), n (cols), t (weight), and a constant `d`
    /// used in `d-linear` codes. Also note the fact that `rows < cols` and `d < cols`.
    /*fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error>;*/

    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// This procedure can be run multiple times by passing base voles of length `k + t + r` and produces `n` number of lpn voles among which
    /// `k + t + r` voles can be used as base voles to the next iteration and the remaining ones are usable voles. Of course, all of the voles
    /// satisfies the vole correlation,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>, Error>;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization with secure LPN parameters, `k (rows)`, `n (cols)`, `t (weight)`, and a constant `d`
    /// used in `d-linear` codes. Also note the fact that `rows < cols` and `d < cols`.
    /*fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error>;*/
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// This procedure can be run multiple times by passing base voles of length `k + t + r` and produces `n` number of lpn voles among which
    /// `k + t + r` voles can be used as base voles to the next iteration and the remaining ones are usable voles. Of course, all of the voles
    /// satisfies the vole correlation,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}
