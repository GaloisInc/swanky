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
        RandomReceiver as ROTReceiver,
        RandomSender as ROTSender,
        Receiver as OtReceiver,
        Sender as OtSender,
    },
};
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
    pub const N: usize = 1;
    /// The exponent `r` when field is of the form `F(p^r)`.
    pub const R: usize = 1;
}

/// A trait for COPEe Sender.
pub trait CopeeSender
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
    type Msg: Sized + FF;
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
    type Msg: Sized + FF;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error>;
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<(Vec<Self::Msg>, Vec<Self::Msg>), Error>;
}

/// A trait for Copee Receiver
pub trait SVoleReceiver
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::{
        ot::*,
        svole::base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
    };
    use rand::SeedableRng;
    use scuttlebutt::{
        field::{FiniteField as FF, Fp},
        AesRng,
        Block,
        Channel,
        Malicious,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    /// Test copee protocol
    fn test_copee_<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        FE: FF + Send,
        CPSender: CopeeSender<Msg = FE>,
        CPReceiver: CopeeReceiver<Msg = FE>,
    >() {
        let w = Arc::new(Mutex::new(vec![]));
        let w_ = w.clone();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let input = vec![FF::random(&mut rng)];
        let u = input.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut copee_sender = CPSender::init(&mut channel).unwrap();
            let mut w = w.lock().unwrap();
            let gw = copee_sender.send(&mut channel, input).unwrap();
            *w = gw;
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut copee_receiver = CPReceiver::init(&mut channel).unwrap();
        let gv = copee_receiver.receive(&mut channel, u.len()).unwrap();
        let delta = copee_receiver.get_delta();
        handle.join().unwrap();
        let w_ = w_.lock().unwrap();
        for i in 0..u.len() {
            let mut temp = delta.clone();
            temp.mul_assign(u[i]);
            temp.add_assign(gv[i]);
            assert_eq!(w_[i], temp);
        }
    }

    #[test]
    fn test_copee() {
        test_copee_::<
            KosSender,
            KosReceiver,
            Fp,
            copee::Sender<KosSender, Fp>,
            copee::Receiver<KosReceiver, Fp>,
        >();
    }

    /// Testing svole protocol

    fn test_svole<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        FE: FF + Sync + Send,
        CPSender: CopeeSender<Msg = FE>,
        CPReceiver: CopeeReceiver<Msg = FE>,
        BVSender: SVoleSender<Msg = FE>,
        BVReceiver: SVoleReceiver<Msg = FE>,
    >() {
        let u = Arc::new(Mutex::new(vec![]));
        let u_ = u.clone();
        let w = Arc::new(Mutex::new(vec![]));
        let w_ = w.clone();
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
        let v = rvole.receive(&mut channel).unwrap();
        let delta = rvole.get_delta();
        handle.join().unwrap();
        let u_ = u_.lock().unwrap();
        let w_ = w_.lock().unwrap();
        assert_eq!(delta, delta);
        for i in 0..Params::N {
            let mut right = delta.clone();
            if let Some(x) = v.as_ref() {
                right *= x[i];
            }
            right.mul_assign(u_[i]);
            assert_eq!(w_[i], right);
        }
    }

    #[test]
    fn test_base_svole() {
        test_svole::<
            KosSender,
            KosReceiver,
            Fp,
            copee::Sender<KosSender, Fp>,
            copee::Receiver<KosReceiver, Fp>,
            VoleSender<KosSender, copee::Sender<KosSender, Fp>, Fp>,
            VoleReceiver<KosReceiver, copee::Receiver<KosReceiver, Fp>, Fp>,
        >();
    }
}
