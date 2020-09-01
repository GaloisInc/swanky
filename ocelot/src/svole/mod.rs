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
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs COPEe extend on input vector `u` and returns `w` such that
    /// the correlation $w = u\Delta+v$ holds.
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
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays and implements Finite Field trait.
    type Msg: Sized + FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver choice $\Delta$.
    fn delta(&self) -> Self::Msg;
    /// Runs COPEe extend on input size `len` and returns vector `v` such that
    /// the correlation $w = u\Delta+v$ holds.
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
    /// `u8` arrays and implements Finite Field trait.
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
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays and implements Finite Field trait.
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
            CopeeReceiver,
            CopeeSender,
            SVoleReceiver,
            SVoleSender,
        },
    };
    use rand::SeedableRng;
    use scuttlebutt::{
        field::{FiniteField as FF, Fp, Gf128},
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
        let input = vec![FE::PrimeField::random(&mut rng)];
        let u = input.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut copee_sender = CPSender::init(&mut channel, &mut rng).unwrap();
            let mut w = w.lock().unwrap();
            let gw = copee_sender.send(&mut channel, &input).unwrap();
            *w = gw;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut copee_receiver = CPReceiver::init(&mut channel, &mut rng).unwrap();
        let gv = copee_receiver.receive(&mut channel, u.len()).unwrap();
        let delta = copee_receiver.delta();
        handle.join().unwrap();
        let w_ = w_.lock().unwrap();
        for i in 0..u.len() {
            let mut temp = delta.clone();
            temp.mul_assign(to_fpr(u[i]));
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
            CpSender<KosSender, Fp>,
            CpReceiver<KosReceiver, Fp>,
        >();
        /* test_copee_::<
            KosSender,
            KosReceiver,
            Gf128,
            CpSender<KosSender, Gf128>,
            CpReceiver<KosReceiver, Gf128>,
        >();*/
    }

    fn test_svole<
        ROTS: ROTSender + Malicious,
        ROTR: ROTReceiver + Malicious,
        FE: FF + Sync + Send,
        CPSender: CopeeSender<Msg = FE>,
        CPReceiver: CopeeReceiver<Msg = FE>,
        BVSender: SVoleSender<Msg = FE>,
        BVReceiver: SVoleReceiver<Msg = FE>,
    >() {
        let len = 10;

        let u = Arc::new(Mutex::new(vec![]));
        let u_ = u.clone();
        let w = Arc::new(Mutex::new(vec![]));
        let w_ = w.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = BVSender::init(&mut channel, &mut rng).unwrap();
            let mut u = u.lock().unwrap();
            let mut w = w.lock().unwrap();
            let (t1, t2) = vole.send(&mut channel, len, &mut rng).unwrap();
            *u = t1;
            *w = t2;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut rvole = BVReceiver::init(&mut channel, &mut rng).unwrap();
        let v = rvole.receive(&mut channel, len, &mut rng).unwrap();
        let delta = rvole.delta();
        handle.join().unwrap();
        let u_ = u_.lock().unwrap();
        let w_ = w_.lock().unwrap();
        assert_eq!(delta, delta);
        for i in 0..len {
            let mut right = delta.clone();
            right.mul_assign(to_fpr(u_[i]));
            if let Some(x) = v.as_ref() {
                right += x[i];
            }
            assert_eq!(w_[i], right);
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
        >();
    }
}
