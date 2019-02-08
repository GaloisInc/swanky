// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

mod alsz;
mod chou_orlandi;
mod dummy;
mod naor_pinkas;

pub use alsz::AlszOT;
pub use chou_orlandi::ChouOrlandiOT;
pub use dummy::DummyOT;
pub use naor_pinkas::NaorPinkasOT;

use crate::Block;
use failure::Error;
use std::io::{BufReader, BufWriter, Read, Write};

/// Oblivious transfer trait for 128-bit inputs.
pub trait BlockObliviousTransfer<T: Read + Write + Send + Sync> {
    /// Creates a new oblivious transfer instance using `stream` for I/O.
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
