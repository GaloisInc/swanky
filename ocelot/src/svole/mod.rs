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
    ot::{
        RandomReceiver as ROTReceiver, RandomSender as ROTSender, Receiver as OtReceiver,
        Sender as OtSender,
    },
};
//use rand::{Rng, SeedableRng};
use scuttlebutt::{field::Fp, AbstractChannel};

/// A type for security parameters
pub struct Params;

impl Params {
    /// Security parameter kappa.
    pub const KAPPA: usize = 128;
    /// Prime field modulus.
    pub const PRIME: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297; // 2^128-159
    /// The number of bits required to represent a field element
    pub const M: usize = 128; // log PRIME
    /// Input length
    pub const N: usize = 20; // Input length
    /// The exponent of the modulus
    pub const R: usize = 1; //
}

/// Aliasing Fp to be consistant with the notation of the algorithm(s).
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

/// A trait for Copee Receiver.
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
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Fpr>>;
}

/*
#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::ot::*;
    use crate::svole::*;
    use num::pow;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Block, Channel, Malicious, field::Fp};
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

    fn test_Copee_init<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        CPSender: CopeeSender<Msg = Block>,
        CPReceiver: CopeeReceiver<Msg = Block>,
    >(// ninputs: usize,
    ) {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let delta: Fp = Fp::random(&mut rng);
        let bs: Vec<bool> = delta.bit_composition();
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let
            assert_eq!(samples.len(), 128);
            let mut out = out.lock().unwrap();
            *out = samples;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let (_, _, results): (_, _, Vec<Block>) = CPReceiver::init(&mut channel).unwrap();
        //let results = otext.receive_random(&mut channel, &bs, &mut rng).unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..Params::R*Params::M{
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    #[test]
    fn test_init() {
        test_Copee_init::<
            KosSender,
            KosReceiver,
            copee::Sender<KosSender>,
            copee::Receiver<KosReceiver>,
        >();
    }
    
}
*/