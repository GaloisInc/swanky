// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licfensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

pub mod eq;
mod ggm_utils;
pub mod sp_svole_dummy_ggmprime;
mod svole_lpn;

use crate::errors::Error;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A trait for EqSender.
pub trait EqSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init() -> Result<Self, Error>;
    /// Returns either a bool value or error on inputting a field element indicating that the
    /// it doesn't match with the receiver input element.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &Self::Msg,
    ) -> Result<bool, Error>;
}

/// A trait for EqReceiver.
pub trait EqReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init() -> Result<Self, Error>;
    /// Returns either a bool value or error on inputting a field element indicating that the
    /// it doesn't match with the sender input element.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        input: &Self::Msg,
    ) -> Result<bool, Error>;
}

/// A trait for SpsVole Sender.
pub trait SpsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Runs single-point svole and outputs pair of vectors `(u, w)` such that
    /// the correlation `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. For simplicity, the vector
    /// length `len` assumed to be power of `2` as it represents the number of leaves in the GGM tree
    /// and should match with the receiver input length.
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: u128,
        rng: &mut RNG,
    ) -> Result<Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>, Error>;
}

/// A trait for SpsVole Receiver.
pub trait SpsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// Runs single-point svole and outputs a vector `v` such that
    /// the correlation `w = u'Δ + v` holds. Again, `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. Of course, the vector
    /// length `len` is suppose to be in multiples of `2` as it represents the number of
    /// leaves in the GGM tree and should match with the sender input length.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: u128,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// This procedure can be run multiple times and produces `cols - rows` sVole correlations,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. `weight` represents the hamming weight of the
    /// error vecor `e` used in the LPN assumption and is suppose to be less than `cols`. Of course, it should also
    /// match with receiver input.
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>, Error>;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization. `rows` and `cols` represent the the number of rows and columns of the
    /// matrix used in the LPN assumption, and `d` represent small constant used in `d-local linear codes` where each
    /// column of the matrix holds `d` non-zero entries uniformly. Also note that it is assumed, `rows < cols` and `d < cols`.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// This procedure can be run multiple times and produces `cols - rows` sVole correlations,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. `weight` represents the hamming weight of the
    /// error vecor `e` used in the LPN assumption and is suppose to be less than `cols`. Of course, it should also
    /// match with sender input.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

#[cfg(test)]
mod tests {
    use crate::{
        ot::{
            ChouOrlandiReceiver,
            ChouOrlandiSender,
            KosReceiver,
            KosSender,
            Receiver as OtReceiver,
            Sender as OtSender,
        },
        svole::{
            base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
            copee::{Receiver as CpReceiver, Sender as CpSender},
            svole_ext::{
                eq::{Receiver as eqReceiver, Sender as eqSender},
                sp_svole_dummy_ggmprime::{Receiver as SpsReceiver, Sender as SpsSender},
                svole_lpn::{Receiver as LpnReceiver, Sender as LpnSender},
                EqReceiver,
                EqSender,
                LpnsVoleReceiver,
                LpnsVoleSender,
                SpsVoleReceiver,
                SpsVoleSender,
            },
            svole_utils::{dot_product, to_fpr},
            CopeeReceiver,
            CopeeSender,
            SVoleReceiver,
            SVoleSender,
        },
    };
    use num::pow;
    use rand::*;
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

    fn test_spsvole<
        FE: FF + Sync + Send,
        SPSender: SpsVoleSender<Msg = FE>,
        SPReceiver: SpsVoleReceiver<Msg = FE>,
    >(
        len: u128,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = SPSender::init(&mut channel, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rvole = SPReceiver::init(&mut channel, &mut rng).unwrap();
        let vs = rvole.receive(&mut channel, len, &mut rng).unwrap();
        let delta = rvole.delta();
        let uw_s = handle.join().unwrap();
        for i in 0..len as usize {
            let mut right = delta.clone();
            right.mul_assign(to_fpr(uw_s[i].0));
            right.add_assign(vs[i]);
            assert_eq!(uw_s[i].1, right);
        }
    }

    #[test]
    fn test_sp_svole() {
        let depth = rand::thread_rng().gen_range(1, 20);
        let leaves = pow(2, depth);
        /*let alpha = leaves - 1;
        test_spsvole::<
            Gf128,
            SpsSender<
                ChouOrlandiReceiver,
                Gf128,
                VoleSender<CpSender<KosSender, Gf128>, Gf128>,
                eqSender<Gf128>,
            >,
            SpsReceiver<
                ChouOrlandiSender,
                Gf128,
                VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
                eqReceiver<Gf128>,
            >,
        >(leaves);*/
        test_spsvole::<
            Gf128,
            SpsSender<
                ChouOrlandiReceiver,
                Gf128,
                VoleSender<CpSender<KosSender, Gf128>, Gf128>,
                eqSender<Gf128>,
            >,
            SpsReceiver<
                ChouOrlandiSender,
                Gf128,
                VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
                eqReceiver<Gf128>,
            >,
        >(leaves);
    }

    fn test_svole_lpn<
        FE: FF + Sync + Send,
        Lpnsender: LpnsVoleSender<Msg = FE>,
        Lpnreciever: LpnsVoleReceiver<Msg = FE>,
    >() {
        println!("Hello");
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut svole_lpn_sender = Lpnsender::init(&mut channel, 2, 3, 1, &mut rng).unwrap();
            //svole_lpn_sender.send(&mut channel, 2, &mut rng).unwrap()
        });
        //assert_eq!(0, 1);
        println!("Im here in testing");
        //let mut svole_lpn_receiver = Lpnreciever::init(&mut channel, 2, 3, 2, &mut rng).unwrap();
        /* let vs = svole_lpn_receiver
            .receive(&mut channel, 2, &mut rng)
            .unwrap();
        let delta = svole_lpn_receiver.delta();
        let uw_s = handle.join().unwrap();*/
        /*for i in 0..len as usize {
            let mut right = delta.clone();
            right.mul_assign(to_fpr(uw_s[i].0));
            right.add_assign(vs[i]);
            assert_eq!(uw_s[i].1, right);
        }*/
    }

    /*#[test]
    fn test_svole_lpn_() {
        test_svole_lpn::<
            Gf128,
            LpnSender<
                Gf128,
                VoleSender<CpSender<KosSender, Gf128>, Gf128>,
                DummySender<
                    ChouOrlandiReceiver,
                    Gf128,
                    VoleSender<CpSender<KosSender, Gf128>, Gf128>,
                    eqSender<Gf128>,
                >,
            >,
            LpnReceiver<
                Gf128,
                VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
                DummyReceiver<
                    ChouOrlandiSender,
                    Gf128,
                    VoleReceiver<CpReceiver<KosReceiver, Gf128>, Gf128>,
                    eqReceiver<Gf128>,
                >,
            >,
        >();
    }*/
}
