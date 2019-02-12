// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

mod alsz;
mod chou_orlandi;
mod dummy;
mod kos;
mod naor_pinkas;

pub use alsz::AlszOT;
pub use chou_orlandi::ChouOrlandiOT;
pub use dummy::DummyOT;
pub use kos::KosOT;
pub use naor_pinkas::NaorPinkasOT;

use crate::Block;
use failure::Error;
use std::io::{BufReader, BufWriter, Read, Write};

/// A trait for one-out-of-two oblivious transfer on 128-bit inputs.
pub trait BlockObliviousTransfer<T: Read + Write + Send + Sync> {
    /// Creates a new oblivious transfer instance.
    fn new() -> Self;
    /// Sends values.
    fn send(
        &mut self,
        reader: &mut BufReader<T>,
        writer: &mut BufWriter<T>,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error>;
    /// Receives values.
    fn receive(
        &mut self,
        reader: &mut BufReader<T>,
        writer: &mut BufWriter<T>,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error>;
}

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious {}

// Fixed key for AES hash. This is the same fixed key as used in the EMP toolkit.
const FIXED_KEY: [u8; 16] = [
    0x61, 0x7e, 0x8d, 0xa2, 0xa0, 0x51, 0x1e, 0x96, 0x5e, 0x41, 0xc2, 0x9b, 0x15, 0x3f, 0xc7, 0x7a,
];
