// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe) and Subfield
//! Vector Oblivious Linear Evaluation (SVOLE) traits.

pub mod base_svole;
pub mod copee;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A trait for COPEe Sender.
pub trait CopeeSender
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs COPEe extend on input vector `u` and returns vector `w` such that
    /// the correlation `w = uΔ + v` holds.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &[<Self::Msg as FF>::PrimeField],
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// A trait for COPEe Receiver.
pub trait CopeeReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver choice `Δ`.
    fn delta(&self) -> Self::Msg;
    /// Runs COPEe extend on input size `len` and returns vector `v` such that
    /// the correlation `w = uΔ + v` holds.
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
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs sVole extend on input length `len` and returns `(u, w)`, where `u`
    /// is a randomly generated input vector of length `len`, such that
    /// the correlation $w = u\Delta+v$ holds.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<(Vec<<Self::Msg as FF>::PrimeField>, Vec<Self::Msg>), Error>;
}

/// A trait for sVole Receiver
pub trait SVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns Receiver's choice $\Delta$.
    fn delta(&self) -> Self::Msg;
    /// Runs sVole extend on input length `len` and returns `v` such that
    /// the correlation $w = u\Delta+v$ holds.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Option<Vec<Self::Msg>>, Error>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    use super::*;
    use crate::{
        ot::{KosReceiver, KosSender, RandomReceiver as ROTReceiver, RandomSender as ROTSender},
        svole::{
            base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
            copee::{to_fpr, Receiver as CpReceiver, Sender as CpSender},
            CopeeReceiver, CopeeSender, SVoleReceiver, SVoleSender,
        },
    };
    use scuttlebutt::{
        field::{FiniteField as FF, Fp, Gf128, F2},
        AesRng, Channel, Malicious,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_copee_<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        FE: FF + Send,
        CPSender: CopeeSender<Msg = FE>,
        CPReceiver: CopeeReceiver<Msg = FE>,
    >(
        len: usize,
    ) {
        let mut rng = AesRng::new();
        let input: Vec<FE::PrimeField> =
            (0..len).map(|_| FE::PrimeField::random(&mut rng)).collect();
        let us = input.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut copee_sender = CPSender::init(&mut channel, &mut rng).unwrap();
            copee_sender.send(&mut channel, &input).unwrap()
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut copee_receiver = CPReceiver::init(&mut channel, &mut rng).unwrap();
        let vs = copee_receiver.receive(&mut channel, us.len()).unwrap();
        let delta = copee_receiver.delta();
        let ws = handle.join().unwrap();
        for i in 0..us.len() {
            let mut temp = delta.clone();
            temp.mul_assign(to_fpr(us[i]));
            temp.add_assign(vs[i]);
            assert_eq!(ws[i], temp);
        }
    }

    #[test]
    fn test_copee() {
        test_copee_::<
            KosSender,
            KosReceiver,
            Fp,
            CpSender<KosSender, Fp>,
            CpReceiver<KosReceiver, Fp>,
        >(1024);
        test_copee_::<
            KosSender,
            KosReceiver,
            Gf128,
            CpSender<KosSender, Gf128>,
            CpReceiver<KosReceiver, Gf128>,
        >(1024);
        test_copee_::<
            KosSender,
            KosReceiver,
            F2,
            CpSender<KosSender, F2>,
            CpReceiver<KosReceiver, F2>,
        >(1024);
    }

    fn test_svole<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        FE: FF + Sync + Send,
        CPSender: CopeeSender<Msg = FE>,
        CPReceiver: CopeeReceiver<Msg = FE>,
        BVSender: SVoleSender<Msg = FE>,
        BVReceiver: SVoleReceiver<Msg = FE>,
    >(
        len: usize,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = BVSender::init(&mut channel, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut rvole = BVReceiver::init(&mut channel, &mut rng).unwrap();
        let vs = rvole.receive(&mut channel, len, &mut rng).unwrap();
        let delta = rvole.delta();
        let (us, ws) = handle.join().unwrap();
        let vs = vs.unwrap();
        for i in 0..len {
            let mut right = delta.clone();
            right.mul_assign(to_fpr(us[i]));
            right.add_assign(vs[i]);
            assert_eq!(ws[i], right);
        }
    }

    #[test]
    fn test_base_svole() {
        test_svole::<
            KosSender,
            KosReceiver,
            Fp,
            CpSender<KosSender, Fp>,
            CpReceiver<KosReceiver, Fp>,
            VoleSender<CpSender<KosSender, Fp>, Fp>,
            VoleReceiver<CpReceiver<KosReceiver, Fp>, Fp>,
        >(1024);
        test_svole::<
            KosSender,
            KosReceiver,
            Gf128,
            CpSender<KosSender, Gf128>,
            CpReceiver<KosReceiver, Gf128>,
            VoleSender<CpSender<KosSender, Gf128>, Gf128>,
            VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
        >(1024);
        test_svole::<
            KosSender,
            KosReceiver,
            F2,
            CpSender<KosSender, F2>,
            CpReceiver<KosReceiver, F2>,
            VoleSender<CpSender<KosSender, F2>, F2>,
            VoleReceiver<CpReceiver<KosReceiver, F2>, F2>,
        >(1024);
    }
}
