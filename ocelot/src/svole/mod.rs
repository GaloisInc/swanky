// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe) and Subfield
//! Vector Oblivious Linear Evaluation (SVOLE) traits.
//!
pub mod base_svole;
pub mod copee;
pub mod svole_ext;
/// sVole related helper functions.
pub mod svole_utils;
use crate::errors::Error;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A trait for COPEe Sender.
pub trait CopeeSender
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs COPEe extend on a prime field element `u` and returns an extended field element `w`
    /// such that `w = u'Δ + v` holds, where `u'` is result of the conversion from `u` to the extended field element.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &<Self::Msg as FF>::PrimeField,
    ) -> Result<Self::Msg, Error>;
}

/// A trait for COPEe Receiver.
pub trait CopeeReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver choice `Δ`.
    fn delta(&self) -> Self::Msg;
    /// Runs COPEe extend and returns a field element `v` such that `w = u'Δ + v` holds.
    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Self::Msg, Error>;
}

/// A trait for sVole Sender.
pub trait SVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs sVole extend on input length `len` and returns `(u, w)`, where `u`
    /// is a randomly generated input vector of length `len` from `FE::PrimeField` such that
    /// the correlation `w = u'Δ + v`, `u'` is the converted vector of `u` to the vector of type `FE`, holds.
    /// The vector length `len` should match with the Receiver's input length, otherwise, the program runs forever.
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>, Error>;
}

/// A trait for sVole Receiver
pub trait SVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that implement the `FiniteField`
    /// trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver choice `Δ`.
    fn delta(&self) -> Self::Msg;
    /// Runs sVole extend on input length `len` and returns a vector `v` such that
    /// the correlation `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    /// The vector length `len` should match with the Sender's input `len`, otherwise it never terminates.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

#[cfg(test)]
mod tests {
    use crate::{
        ot::{KosReceiver, KosSender, RandomReceiver as ROTReceiver, RandomSender as ROTSender},
        svole::{
            base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
            copee::{Receiver as CpReceiver, Sender as CpSender},
            svole_utils::to_fpr,
            CopeeReceiver,
            CopeeSender,
            SVoleReceiver,
            SVoleSender,
        },
    };
    use scuttlebutt::{
        field::{FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
        Malicious,
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
        for _i in 0..len {
            let input = FE::PrimeField::random(&mut rng);
            let u = input.clone();
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
            let v = copee_receiver.receive(&mut channel).unwrap();
            let mut delta = copee_receiver.delta();
            let w = handle.join().unwrap();
            delta.mul_assign(to_fpr(u));
            delta.add_assign(v);
            assert_eq!(w, delta);
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
        >(128);
        test_copee_::<
            KosSender,
            KosReceiver,
            Gf128,
            CpSender<KosSender, Gf128>,
            CpReceiver<KosReceiver, Gf128>,
        >(128);
        test_copee_::<
            KosSender,
            KosReceiver,
            F2,
            CpSender<KosSender, F2>,
            CpReceiver<KosReceiver, F2>,
        >(128);
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
        let uw_s = handle.join().unwrap();
        for i in 0..len {
            let mut right = delta.clone();
            right.mul_assign(to_fpr(uw_s[i].0));
            right.add_assign(vs[i]);
            assert_eq!(uw_s[i].1, right);
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
