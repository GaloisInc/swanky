// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious PRF traits + instantiations.

#[cfg(feature = "cointoss")]
pub mod kkrt;
#[cfg(feature = "cointoss")]
pub mod kmprt;
mod prc;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::AbstractChannel;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tstd::vec::Vec;

/// KKRT oblivious PRF sender using ALSZ OT extension with Chou-Orlandi as the base OT.
#[cfg(feature = "cointoss")]
pub type KkrtSender = kkrt::Sender<ot::AlszReceiver>;
/// KKRT oblivious PRF receiver using ALSZ OT extension with Chou-Orlandi as the base OT.
#[cfg(feature = "cointoss")]
pub type KkrtReceiver = kkrt::Receiver<ot::AlszSender>;
/// KMPRT hash-based OPPRF sender, using KKRT as the underlying OPRF.
#[cfg(feature = "cointoss")]
pub type KmprtSender = kmprt::Sender<KkrtSender>;
/// KMPRT hash-based OPPRF receiver, using KKRT as the underlying OPRF.
#[cfg(feature = "cointoss")]
pub type KmprtReceiver = kmprt::Receiver<KkrtReceiver>;

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
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs `m` OPRF instances as the sender, returning the OPRF seeds.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
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
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs the oblivious PRF on inputs `inputs`, returning the OPRF outputs.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>;
}
