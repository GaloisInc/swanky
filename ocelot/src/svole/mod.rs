// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides traits COPEe

pub mod base_svole;
pub mod copee;
#[allow(unused_imports)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
//use rand::{Rng, SeedableRng};
use scuttlebutt::{ff_derive::Fp, AbstractChannel};

/// A type for security parameters
pub struct Params;

impl Params {
    pub const KAPPA: usize = 128;
    // pub const ELL: usize = 127;
    pub const M: usize = 10;
    pub const PRIME: usize = 7;
    pub const N: usize = 20;
    pub const POWR: usize = 5; //52435875175126190479447740508185965837690552500527637822603658699938581184513;
                               //pub const N: usize = 2 ^ Params::ELL;
}

type Fpr = Fp;

/// A trait for COPEe Sender.
pub trait CopeeSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<Fp>,
    ) -> Result<Vec<Fpr>, Error>;
}

/// A trait for Copee Receiver
pub trait CopeeReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Fpr), Error>;

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<Fpr>, Error>;
}

/// A trait for sVole Sender.
pub trait SVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    fn send<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<(Vec<Fpr>, Vec<Fpr>), Error>;
}

/// A trait for Copee Receiver
pub trait SVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init() -> Result<Self, Error>;

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Fpr>>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::svole::*;
    use scuttlebutt::{AesRng, Block, Channel};
    use std::{
        fmt::Display,
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }
}
