// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod alsz;
pub mod chou_orlandi;
pub mod dummy;
pub mod kos;
pub mod naor_pinkas;

use failure::Error;
use std::io::{Read, Write};

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
pub trait ObliviousTransferSender<R: Read, W: Write>
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init(reader: &mut R, writer: &mut W) -> Result<Self, Error>;
    /// Sends values.
    fn send(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
    ) -> Result<(), Error>;
}

/// Trait for one-out-of-two oblivious transfer from the receiver's
/// point-of-view.
pub trait ObliviousTransferReceiver<R: Read, W: Write>
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init(reader: &mut R, writer: &mut W) -> Result<Self, Error>;
    /// Receives values.
    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two correlated oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedObliviousTransferSender<R: Read, W: Write>:
    ObliviousTransferSender<R, W>
where
    Self: Sized,
{
    fn send_correlated(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
    ) -> Result<(), Error>;
}

/// Trait for one-out-of-two correlated oblivious transfer from the receiver's
/// point-of-view.
pub trait CorrelatedObliviousTransferReceiver<R: Read, W: Write>:
    ObliviousTransferReceiver<R, W>
where
    Self: Sized,
{
    fn receive_correlated(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deltas: &[bool],
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious {}
