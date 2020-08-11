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
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    /// To retrieve delta from the receiver type.
    fn get_delta(&self) -> Fpr;
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
    /// To retrieve delta from the receiver type.
    fn get_delta(&self) -> Fpr;
    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Fpr>>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::ot::*;
    use crate::svole::{base_svole::Receiver as VoleReceiver, base_svole::Sender as VoleSender};
    use rand::SeedableRng;
    use scuttlebutt::{field::Fp, AesRng, Block, Channel, Malicious};
    use std::{
        fmt::Display,
        io::{BufReader, BufWriter},
        ops::{AddAssign, MulAssign},
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
        BVSender: SVoleSender<Msg = Block>,
        BVReceiver: SVoleReceiver<Msg = Block>,
    >() {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let delta: Fp = Fp::random(&mut rng);
        let bs: Vec<bool> = delta.bit_composition();
        let u = Arc::new(Mutex::new(vec![]));
        let mut u_ = u.clone();
        let w = Arc::new(Mutex::new(vec![]));
        let w_ = u.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = BVSender::init(&mut channel).unwrap();
            let mut u = u.lock().unwrap();
            let mut w = w.lock().unwrap();
            let (t1, t2) = vole.send(&mut channel).unwrap();
            *u = t1;
            *w = t2;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut rvole = BVReceiver::init(&mut channel).unwrap();
        let mut v = rvole.receive(&mut channel).unwrap();
        let delta = rvole.get_delta();
        handle.join().unwrap();
        let mut u_ = u_.lock().unwrap();
        let w_ = w_.lock().unwrap();
        for i in 0..Params::N {
            u_[i].mul_assign(&delta);
            v[i].add_assign(&u_[i]);
            assert_eq!(w_[i], v[i])
        }
    }

    #[test]
    fn test_init() {
        test_Copee_init::<
            KosSender,
            KosReceiver,
            copee::Sender<KosSender>,
            copee::Receiver<KosReceiver>,
            VoleSender<KosSender, copee::Sender<KosSender>>,
            VoleReceiver<KosReceiver, copee::Receiver<KosReceiver>>,
        >();
    }
}
