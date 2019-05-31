// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious PRF traits + instantiations.

pub mod kkrt;
#[cfg(feature = "unstable")]
pub mod kmprt;
mod prc;

use crate::errors::Error;
use crate::ot;
use rand::{CryptoRng, RngCore};
use scuttlebutt::Channel;
use std::io::{Read, Write};

/// KKRT oblivious PRF sender using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtSender = kkrt::Sender<ot::AlszReceiver>;
/// KKRT oblivious PRF receiver using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtReceiver = kkrt::Receiver<ot::AlszSender>;

/// Trait containing the associated types used by an oblivious PRF.
pub trait ObliviousPrf
where
    Self: Sized,
{
    /// PRF seed.
    type Seed: Sized;
    /// PRF input.
    type Input: Sized;
    /// PRF output.
    type Output: Sized;
}

/// Trait for an oblivious PRF sender.
pub trait Sender: ObliviousPrf
where
    Self: Sized,
{
    /// Runs any one-time initialization.
    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        channel: &mut Channel<R, W>,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs `m` OPRF instances as the sender, returning the OPRF seeds.
    fn send<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut Channel<R, W>,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Seed>, Error>;
    /// Computes the oblivious PRF on seed `seed` and input `input`.
    fn compute(&self, seed: Self::Seed, input: Self::Input) -> Self::Output;
}

/// Trait for an oblivious PRF receiver.
pub trait Receiver: ObliviousPrf
where
    Self: Sized,
{
    /// Runs any one-time initialization.
    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        channel: &mut Channel<R, W>,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs the oblivious PRF on inputs `inputs`, returning the OPRF outputs.
    fn receive<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut Channel<R, W>,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>;
}

/// Trait containing the associated types used by an oblivious programmable PRF.
#[cfg(feature = "unstable")]
pub trait ObliviousPprf: ObliviousPrf {
    /// PRF hint.
    type Hint: Sized;
}

/// Trait for an oblivious programmable PRF sender.
#[cfg(feature = "unstable")]
pub trait ProgrammableSender: ObliviousPprf {
    /// Runs any one-time initialization.
    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        channel: &mut Channel<R, W>,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs `m` OPRF instances as the sender, returning the OPRF seeds.
    fn send<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut Channel<R, W>,
        points: &[(Self::Input, Self::Output)],
        // Max number of points allowed.
        npoints: usize,
        ninputs: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Seed, Self::Hint)>, Error>;
    /// Computes the oblivious PRF on seed `seed` and input `input`.
    fn compute(&self, seed: &Self::Seed, hint: &Self::Hint, input: &Self::Input) -> Self::Output;
}

/// Trait for an oblivious programmable PRF receiver.
#[cfg(feature = "unstable")]
pub trait ProgrammableReceiver: ObliviousPprf {
    /// Runs any one-time initialization.
    fn init<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        channel: &mut Channel<R, W>,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs the oblivious PRF on inputs `inputs`, returning the OPRF outputs.
    fn receive<R: Read, W: Write, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut Channel<R, W>,
        // Max number of points allowed.
        npoints: usize,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>;
}
