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

use failure::Error;
use std::io::{Read, Write};

/// Trait for one-out-of-two oblivious transfer on 128-bit inputs.
///
/// This trait encapsulates the functionality common to oblivious transfer
/// protocols.
pub trait ObliviousTransfer<R: Read, W: Write> {
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;

    /// Creates a new oblivious transfer instance.
    fn new() -> Self;
    /// Sends values.
    fn send(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
    ) -> Result<(), Error>;
    /// Receives values.
    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious {}
