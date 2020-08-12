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
use scuttlebutt::AbstractChannel;

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
        input: Vec<Self::Msg>,
    ) -> Result<Vec<Self::Msg>, Error>;
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
    fn get_delta(&self) -> Self::Msg;
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<Self::Msg>, Error>;
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
    fn send<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<(Vec<Self::Msg>, Vec<Self::Msg>), Error>;
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
    fn get_delta(&self) -> Self::Msg;
    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Option<Vec<Self::Msg>>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::ot::*;
    use crate::utils::bit_composition;
    use crate::svole::{
        base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
    };
    use scuttlebutt::{field::Fp, Channel, Malicious};
    use std::{
        io::{BufReader, BufWriter},
        ops::{AddAssign, MulAssign},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };


    fn test_copee_init<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        CPSender: CopeeSender<Msg = Fp>,
        CPReceiver: CopeeReceiver<Msg = Fp>,
        BVSender: SVoleSender<Msg = Fp>,
        BVReceiver: SVoleReceiver<Msg = Fp>,
    >() {
        let u = Arc::new(Mutex::new(vec![]));
        let u_ = u.clone();
        let w = Arc::new(Mutex::new(vec![]));
        let w_ = u.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
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
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut rvole = BVReceiver::init(&mut channel).unwrap();
        let mut v = rvole.receive(&mut channel).unwrap();
        let delta = rvole.get_delta();
        let bs = bit_composition(delta);
        handle.join().unwrap();
        let mut u_ = u_.lock().unwrap();
        let w_ = w_.lock().unwrap();
        for i in 0..Params::N {
            if bs[i] == true {
            u_[i].mul_assign(&Fp::one());
            }
            else {
                u_[i].mul_assign(&Fp::zero());
            }
            v[i].add_assign(&u_[i]);
            assert_eq!(w_[i], v[i])
        }
    }

    #[test]
    fn test_init() {
        test_copee_init::<
            KosSender,
            KosReceiver,
            copee::Sender<KosSender>,
            copee::Receiver<KosReceiver>,
            VoleSender<KosSender, copee::Sender<KosSender>>,
            VoleReceiver<KosReceiver, copee::Receiver<KosReceiver>>,
        >();
    }
}
