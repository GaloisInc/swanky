// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides traits COPEe

mod sp_svole;

use crate::errors::Error;
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A type for security parameters
pub struct Params;

impl Params {
    /// Security parameter kappa.
    /*pub const KAPPA: usize = 128;
    /// Prime field modulus.
    pub const PRIME: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297; // 2^128-159*/
    /// The number of bits required to represent a field element
    //pub const M: usize = 128;
    /// Input length
    pub const H: usize = 3;
    /// The exponent `r` when field is of the form `F(p^r)`.
    pub const N: usize = 2 ^ (Params::H);
}

/// A trait for SpsVole Sender.
pub trait SpsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + FF;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<(Vec<<Self::Msg as FF>::PrimeField>, Vec<Self::Msg>), Error>;
}

/// A trait for SpsVole Sender.
pub trait SpsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + FF;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    /// To retrieve delta from the receiver type.
    fn get_delta(&self) -> Self::Msg;
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<Option<Vec<Self::Msg>>, Error>;
}
