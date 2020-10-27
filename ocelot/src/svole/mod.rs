// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe) and Subfield
//! Vector Oblivious Linear Evaluation (SVOLE) traits.
//!
pub mod base_svole;
pub mod copee;
pub mod svole_ext;
mod utils;

// use crate::errors::Error;
// use rand_core::{CryptoRng, RngCore};
// use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

// /// A trait for COPEe sender.
// pub trait CopeeSender
// where
//     Self: Sized,
// {
//     /// Message type, restricted to types that implement the `FiniteField`
//     /// trait.
//     type Msg: FF;
//     /// Runs any one-time initialization.
//     fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
//         channel: &mut C,
//         rng: &mut RNG,
//     ) -> Result<Self, Error>;
//     /// Runs COPEe extend on a prime field element `u` and returns an extended
//     /// field element `w` such that `w = u'Δ + v` holds, where `u'` is result of
//     /// the conversion from `u` to the extended field element.
//     fn send<C: AbstractChannel>(
//         &mut self,
//         channel: &mut C,
//         input: &<Self::Msg as FF>::PrimeField,
//     ) -> Result<Self::Msg, Error>;
// }

// /// A trait for COPEe receiver.
// pub trait CopeeReceiver
// where
//     Self: Sized,
// {
//     /// Message type, restricted to types that implement the `FiniteField`
//     /// trait.
//     type Msg: FF;
//     /// Runs any one-time initialization.
//     fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
//         channel: &mut C,
//         rng: &mut RNG,
//     ) -> Result<Self, Error>;
//     /// Returns the receiver choice `Δ`.
//     fn delta(&self) -> Self::Msg;
//     /// Runs COPEe extend and returns a field element `v` such that `w = u'Δ +
//     /// v` holds.
//     fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Self::Msg, Error>;
// }
