// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod psz;

use crate::errors::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

pub trait PrivateSetIntersectionSender
where
    Self: Sized,
{
    fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}

pub trait PrivateSetIntersectionReceiver
where
    Self: Sized,
{
    fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}
