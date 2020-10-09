// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licfensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

pub mod eq;
/// GGM related helper functions.
mod ggm_utils;
pub mod lpn_params;
pub mod sp_svole_dummy_ggmprime;
pub mod svole_lpn;

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
        len: usize,
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
        len: usize,
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
        ot::{ChouOrlandiReceiver, ChouOrlandiSender, KosReceiver, KosSender},
        svole::{
            base_svole::{Receiver as VoleReceiver, Sender as VoleSender},
            copee::{Receiver as CpReceiver, Sender as CpSender},
            svole_ext::{
                eq::{Receiver as EqReceiver, Sender as EqSender},
                lpn_params::{LpnExtendParams, LpnSetupParams},
                sp_svole_dummy_ggmprime::{Receiver as SpsReceiver, Sender as SpsSender},
                svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
                LpnsVoleReceiver,
                LpnsVoleSender,
                SpsVoleReceiver,
                SpsVoleSender,
            },
        },
    };
    use scuttlebutt::{
        field::{FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_spsvole<
        FE: FF,
        SPSender: SpsVoleSender<Msg = FE>,
        SPReceiver: SpsVoleReceiver<Msg = FE>,
    >(
        len: usize,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = SPSender::init(&mut channel, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = SPReceiver::init(&mut channel, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, len, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..len as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    type CPSender<FE> = CpSender<KosSender, FE>;
    type CPReceiver<FE> = CpReceiver<KosReceiver, FE>;

    type BVSender<FE> = VoleSender<CPSender<FE>, FE>;
    type BVReceiver<FE> = VoleReceiver<CPReceiver<FE>, FE>;

    type SPSender<FE> = SpsSender<ChouOrlandiReceiver, FE, BVSender<FE>, EqSender<FE>>;
    type SPReceiver<FE> = SpsReceiver<ChouOrlandiSender, FE, BVReceiver<FE>, EqReceiver<FE>>;

    #[test]
    fn test_sp_svole() {
        for i in 1..10 {
            let leaves = 1 << i;
            test_spsvole::<Fp, SPSender<Fp>, SPReceiver<Fp>>(leaves);
            test_spsvole::<Gf128, SPSender<Gf128>, SPReceiver<Gf128>>(leaves);
            test_spsvole::<F2, SPSender<F2>, SPReceiver<F2>>(leaves);
        }
    }

    fn test_lpnvole<
        FE: FF,
        VSender: LpnsVoleSender<Msg = FE>,
        VReceiver: LpnsVoleReceiver<Msg = FE>,
    >(
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        debug_assert!(cols % weight == 0);
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = VSender::init(&mut channel, rows, cols, d, &mut rng).unwrap();
            vole.send(&mut channel, weight, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = VReceiver::init(&mut channel, rows, cols, d, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, weight, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..weight as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    type VSender<FE> = LpnVoleSender<FE, BVSender<FE>, SPSender<FE>>;
    type VReceiver<FE> = LpnVoleReceiver<FE, BVReceiver<FE>, SPReceiver<FE>>;

    #[test]
    fn test_lpn_svole_setup() {
        let cols = LpnSetupParams::COLS;
        let rows = LpnSetupParams::ROWS;
        let weight = LpnSetupParams::WEIGHT;
        let d = LpnSetupParams::D;
        test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
        test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
        //test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);
    }
    
    #[test]
    fn test_lpn_svole_extend() {
        let cols = LpnExtendParams::COLS;
        let rows = LpnExtendParams::ROWS;
        let weight = LpnExtendParams::WEIGHT;
        let d = LpnExtendParams::D;
        test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
        test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
        //test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);
    }

}
