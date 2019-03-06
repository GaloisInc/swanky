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

use crate::errors::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
pub trait ObliviousTransferSender
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
    /// Sends values.
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
pub trait ObliviousTransferReceiver
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
    /// Receives values.
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
pub trait CorrelatedObliviousTransferSender: ObliviousTransferSender
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
pub trait CorrelatedObliviousTransferReceiver: ObliviousTransferReceiver
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
pub trait RandomObliviousTransferSender: ObliviousTransferSender
where
    Self: Sized,
{
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
pub trait RandomObliviousTransferReceiver: ObliviousTransferReceiver
where
    Self: Sized,
{
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

    fn test_ot<
        OTSender: ObliviousTransferSender<Msg = Block>,
        OTReceiver: ObliviousTransferReceiver<Msg = Block>,
    >() {
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

    fn test_otext<
        OTSender: ObliviousTransferSender<Msg = Block>,
        OTReceiver: ObliviousTransferReceiver<Msg = Block>,
    >() {
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
        OTSender: CorrelatedObliviousTransferSender<Msg = Block>,
        OTReceiver: CorrelatedObliviousTransferReceiver<Msg = Block>,
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

    fn test_rotext<
        OTSender: RandomObliviousTransferSender<Msg = Block>,
        OTReceiver: RandomObliviousTransferReceiver<Msg = Block>,
    >() {
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

    type AlszSender = alsz::AlszOTSender<chou_orlandi::ChouOrlandiOTReceiver>;
    type AlszReceiver = alsz::AlszOTReceiver<chou_orlandi::ChouOrlandiOTSender>;
    type KosSender = kos::KosOTSender<chou_orlandi::ChouOrlandiOTReceiver>;
    type KosReceiver = kos::KosOTReceiver<chou_orlandi::ChouOrlandiOTSender>;

    #[test]
    fn test_dummy() {
        test_ot::<dummy::DummyOTSender, dummy::DummyOTReceiver>();
    }

    #[test]
    fn test_naor_pinkas() {
        test_ot::<naor_pinkas::NaorPinkasOTSender, naor_pinkas::NaorPinkasOTReceiver>();
    }

    #[test]
    fn test_chou_orlandi() {
        test_ot::<chou_orlandi::ChouOrlandiOTSender, chou_orlandi::ChouOrlandiOTReceiver>();
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
