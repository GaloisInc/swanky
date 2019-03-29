// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Oblivious transfer traits + instantiations.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT.

pub mod alsz;
pub mod chou_orlandi;
pub mod dummy;
pub mod kos;
pub mod naor_pinkas;

use crate::errors::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

/// Instantiation of the Chou-Orlandi OT sender.
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
/// Instantiation of the dummy OT sender.
pub type DummySender = dummy::Sender;
/// Instantiation of the dummy OT receiver.
pub type DummyReceiver = dummy::Receiver;
/// Instantiation of the Naor-Pinkas OT sender.
pub type NaorPinkasSender = naor_pinkas::Sender;
/// Instantiation of the Naor-Pinkas OT receiver.
pub type NaorPinkasReceiver = naor_pinkas::Receiver;
/// Instantiation of the ALSZ OT extension sender, using Chou-Orlandi as the base OT.
pub type AlszSender = alsz::Sender<ChouOrlandiReceiver>;
/// Instantiation of the ALSZ OT extension receiver, using Chou-Orlandi as the base OT.
pub type AlszReceiver = alsz::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub type KosSender = kos::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosReceiver = kos::Receiver<ChouOrlandiSender>;

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
pub trait Sender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Sends messages.
    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut RNG,
    ) -> Result<(), Error>;
}

/// Trait for one-out-of-two oblivious transfer from the receiver's
/// point-of-view.
pub trait Receiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Receives messages.
    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedSender: Sender
where
    Self: Sized,
{
    /// Correlated oblivious transfer send. Takes as input an array `deltas`
    /// which specifies the offset between the zero and one message.
    fn send_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deltas: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the receiver's
/// point-of-view.
pub trait CorrelatedReceiver: Receiver
where
    Self: Sized,
{
    /// Correlated oblivious transfer receive.
    fn receive_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the sender's
/// point-of-view.
pub trait RandomSender: Sender
where
    Self: Sized,
{
    /// Random oblivious transfer send. Returns a vector of tuples containing
    /// the two random messages.
    fn send_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the receiver's
/// point-of-view.
pub trait RandomReceiver: Receiver
where
    Self: Sized,
{
    /// Random oblivious transfer receive.
    fn receive_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deltas: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use scuttlebutt::{AesRng, Block};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const T: usize = 16;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block>>() {
        let m0 = rand::random::<Block>();
        let m1 = rand::random::<Block>();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut ot = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            ot.send(&mut reader, &mut writer, &[(m0, m1)], &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut ot = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let result = ot
            .receive(&mut reader, &mut writer, &[b], &mut rng)
            .unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }

    fn test_otext<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block>>() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut reader, &mut writer, &ms, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let results = otext
            .receive(&mut reader, &mut writer, &bs, &mut rng)
            .unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { m1s_[j] } else { m0s_[j] })
        }
        handle.join().unwrap();
    }

    fn test_cotext<
        OTSender: CorrelatedSender<Msg = Block>,
        OTReceiver: CorrelatedReceiver<Msg = Block>,
    >() {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext
                .send_correlated(&mut reader, &mut writer, &deltas, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let results = otext
            .receive_correlated(&mut reader, &mut writer, &bs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    fn test_rotext<OTSender: RandomSender<Msg = Block>, OTReceiver: RandomReceiver<Msg = Block>>() {
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext
                .send_random(&mut reader, &mut writer, T, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let results = otext
            .receive_random(&mut reader, &mut writer, &bs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    #[test]
    fn test_dummy() {
        test_ot::<DummySender, DummyReceiver>();
    }

    #[test]
    fn test_naor_pinkas() {
        test_ot::<NaorPinkasSender, NaorPinkasReceiver>();
    }

    #[test]
    fn test_chou_orlandi() {
        test_ot::<ChouOrlandiSender, ChouOrlandiReceiver>();
    }

    #[test]
    fn test_alsz() {
        test_otext::<AlszSender, AlszReceiver>();
        test_cotext::<AlszSender, AlszReceiver>();
        test_rotext::<AlszSender, AlszReceiver>();
    }

    #[test]
    fn test_kos() {
        test_otext::<KosSender, KosReceiver>();
        test_cotext::<KosSender, KosReceiver>();
        test_rotext::<KosSender, KosReceiver>();
    }

}
