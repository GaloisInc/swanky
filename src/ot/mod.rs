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

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedObliviousTransferSender<R: Read, W: Write>:
    ObliviousTransferSender<R, W>
where
    Self: Sized,
{
    /// Correlated oblivious transfer send. Takes as input an array `deltas`
    /// which specifies the offset between the zero and one message.
    fn send_correlated(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deltas: &[Self::Msg],
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the receiver's
/// point-of-view.
pub trait CorrelatedObliviousTransferReceiver<R: Read, W: Write>:
    ObliviousTransferReceiver<R, W>
where
    Self: Sized,
{
    /// Correlated oblivious transfer receive.
    fn receive_correlated(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the sender's
/// point-of-view.
pub trait RandomObliviousTransferSender<R: Read, W: Write>: ObliviousTransferSender<R, W>
where
    Self: Sized,
{
    fn send_random(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the receiver's
/// point-of-view.
pub trait RandomObliviousTransferReceiver<R: Read, W: Write>:
    ObliviousTransferReceiver<R, W>
where
    Self: Sized,
{
    fn receive_random(
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

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use scuttlebutt::Block;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    type Reader = BufReader<UnixStream>;
    type Writer = BufWriter<UnixStream>;

    const T: usize = 1 << 12;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_otext<
        OTSender: ObliviousTransferSender<Reader, Writer, Msg = Block>,
        OTReceiver: ObliviousTransferReceiver<Reader, Writer, Msg = Block>,
    >() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut reader, &mut writer, &ms).unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer).unwrap();
        let results = otext.receive(&mut reader, &mut writer, &bs).unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { m1s_[j] } else { m0s_[j] })
        }
        handle.join().unwrap();
    }

    fn test_cotext<
        OTSender: CorrelatedObliviousTransferSender<Reader, Writer, Msg = Block>,
        OTReceiver: CorrelatedObliviousTransferReceiver<Reader, Writer, Msg = Block>,
    >() {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext
                .send_correlated(&mut reader, &mut writer, &deltas)
                .unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer).unwrap();
        let results = otext
            .receive_correlated(&mut reader, &mut writer, &bs)
            .unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    fn test_rotext<
        OTSender: RandomObliviousTransferSender<Reader, Writer, Msg = Block>,
        OTReceiver: RandomObliviousTransferReceiver<Reader, Writer, Msg = Block>,
    >() {
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = OTSender::init(&mut reader, &mut writer).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext.send_random(&mut reader, &mut writer, T).unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = OTReceiver::init(&mut reader, &mut writer).unwrap();
        let results = otext.receive_random(&mut reader, &mut writer, &bs).unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender<Reader, Writer>;
    type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver<Reader, Writer>;
    type AlszSender = alsz::AlszOTSender<Reader, Writer, ChouOrlandiReceiver>;
    type AlszReceiver = alsz::AlszOTReceiver<Reader, Writer, ChouOrlandiSender>;
    type KosSender = kos::KosOTSender<Reader, Writer, ChouOrlandiReceiver>;
    type KosReceiver = kos::KosOTReceiver<Reader, Writer, ChouOrlandiSender>;

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
