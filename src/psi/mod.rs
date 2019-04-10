// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod psty;
pub mod psz;

use crate::errors::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

/// Trait for a private set intersection sender.
pub trait Sender
where
    Self: Sized,
{
    /// Input message type.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization required by the protocol.
    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs the protocol.
    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<(), Error>;
}

/// Trait for a private set intersection receiver.
pub trait Receiver
where
    Self: Sized,
{
    /// Input message type.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization required by the protocol.
    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs the protocol, receiving the intersection as output.
    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}
