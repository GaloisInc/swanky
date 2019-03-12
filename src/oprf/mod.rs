// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod kkrt;
mod prc;

use crate::errors::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

/// Trait for oblivious PRF from the sender's point-of-view.
pub trait ObliviousPrfSender
where
    Self: Sized,
{
    type Seed: Sized;
    type Input: Sized;
    type Output: Sized;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Seed>, Error>;

    fn compute(&self, seed: &Self::Seed, input: &Self::Input) -> Self::Output;
}

/// Trait for oblivious PRF from the receiver's point-of-view.
pub trait ObliviousPrfReceiver
where
    Self: Sized,
{
    type Input: Sized;
    type Output: Sized;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        selections: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>;
}
