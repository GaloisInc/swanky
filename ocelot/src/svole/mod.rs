// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! module defining the interface for `SVoleSender` and `SVoleReceiver`.

pub mod wykw;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// Interface for `SVoleSender`
pub trait SVoleSender
where
    Self: Sized,
{
    /// Message type that implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// This procedure can be run multiple times where each call spits out `n - (k + t + r)` usable voles
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>, Error>;
    /// This procedure duplicates the Sender.
    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}

/// Interface for `SVoleReceiver`
pub trait SVoleReceiver
where
    Self: Sized,
{
    /// Message type that implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns delta.
    fn delta(&self) -> Self::Msg;
    /// This procedure can be run multiple times where each call spits out `n - (k + t + r)` usable voles
    /// i.e, outputs `v` such that `w = u'Δ + v` holds.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
    /// This procedure duplicates the Receiver with the same Δ.
    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}
