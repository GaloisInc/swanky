// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! (Random) subfield vector oblivious linear evaluation (sVOLE) traits +
//! instantiations.
//!
//! This module provides traits for sVOLE, alongside an implementation of the
//! Weng-Yang-Katz-Wang maliciously secure random sVOLE protocol.
//!

pub mod wykw;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// Trait for an sVOLE sender.
pub trait SVoleSender
where
    Self: Sized,
{
    /// Finite field for which sVOLEs are generated.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Generates sVOLEs.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        out: &mut Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>,
    ) -> Result<(), Error>;
    /// Duplicates the sender's state.
    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}

/// Trait for an sVOLE receiver.
pub trait SVoleReceiver
where
    Self: Sized,
{
    /// Finite field for which sVOLEs are generated.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns delta.
    fn delta(&self) -> Self::Msg;
    /// Generates sVOLEs.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        out: &mut Vec<Self::Msg>,
    ) -> Result<(), Error>;
    /// Duplicates the receiver's state.
    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}
