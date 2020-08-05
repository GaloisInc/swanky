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
use scuttlebutt::{ff_derive::*, AbstractChannel, Block};

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
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Vec<(Block, Block)>), Error>;
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
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Fpr, Vec<Block>), Error>;

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
    use crate::ot::*;
    use crate::svole::*;
    use ff::*;
    use num::pow;
    use scuttlebutt::{AesRng, Block, Channel, Malicious};
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
        //let bs = rand_bool_vec(Params::R*Params::);
        let delta: Fp = rand::random::<Fp>();
        let bs: Vec<bool> = unsafe { std::mem::transmute::<Fp, Vec<bool>>(delta) };
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let (mut otext, samples): (_, Vec<(Block, Block)>) =
                CPSender::init(&mut channel).unwrap();
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
        /* for j in 0..Params::R*Params::M{
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }*/
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
    #[test]
    fn check_gen() {
        let g: Fp = PrimeField::multiplicative_generator();
        assert_eq!(g, PrimeField::from_str("5").unwrap());
    }
    #[test]
    fn fp_to_vec() {
        let delta: Fp = rand::random::<Fp>();
        let mut deltab: Vec<bool> = Vec::new();
        let temp_vec = ((delta.0).0).to_vec();
        for i in 0..2 {
            //for e in format!("{:b}", (delta.0).0)[i].chars(){
            for e in format!("{:b}", temp_vec[i]).chars() {
                if e == '1' {
                    deltab.push(true);
                } else {
                    deltab.push(false);
                }
            }
        }

        if deltab.len() > Params::M {
            (Params::M..deltab.len() + 1).map(|_| deltab.pop());
        } else {
            (deltab.len()..Params::M + 1).map(|_| deltab.push(false));
        }
        //println!("{:?}", deltab);
        //assert_eq!(deltab.len(), 128);
        let temp: u128 = (0..(deltab.len())).fold(0, |sum, i| {
            sum + (pow(2, i as usize) * (u128::from(deltab[i])))
        });
        assert_eq!(((delta.0).0)[0] as u128 + ((delta.0).0)[1] as u128, temp);
    }
    #[test]

    fn test_repr() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let writer = BufWriter::new(receiver);
        let x: Fp = rand::random::<Fp>();
        (x.0).write_le(writer);
    }
}
