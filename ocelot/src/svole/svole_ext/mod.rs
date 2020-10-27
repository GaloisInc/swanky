// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licfensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

/// GGM related helper functions.
mod ggm_utils;
pub mod lpn_params;
pub mod sp_svole;
pub mod svole_lpn;

use crate::errors::Error;

use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

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
        weight: usize,
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
        weight: usize,
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
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

#[cfg(test)]
mod tests {
    use crate::svole::svole_ext::{
        lpn_params::{LpnExtendParams, LpnSetupParams},
        svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
        LpnsVoleReceiver,
        LpnsVoleSender,
    };
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

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
            let mut vole = VSender::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap();
            vole.send(&mut channel, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = VReceiver::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..weight as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    type VSender<FE> = LpnVoleSender<FE>;
    type VReceiver<FE> = LpnVoleReceiver<FE>;

    #[test]
    fn test_lpn_svole_params1() {
        let weight = LpnSetupParams::WEIGHT;
        let cols = LpnSetupParams::COLS;
        let rows = LpnSetupParams::ROWS;
        let d = LpnSetupParams::D;
        test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
        test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
        test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);
        test_lpnvole::<F61p, VSender<F61p>, VReceiver<F61p>>(rows, cols, d, weight);
    }
    // This test passes but takes more than 60 seconds.
    // So commenting it out for now to pass `checkfmt:rustfmt` on the repo.
    /* #[test]
    fn test_lpn_svole_params2() {
        let cols = LpnExtendParams::COLS;
        let rows = LpnExtendParams::ROWS;
        let weight = LpnExtendParams::WEIGHT;
        let d = LpnExtendParams::D;
        test_lpnvole::<F2, VSender<F2>, VReceiver<F2>>(rows, cols, d, weight);
        test_lpnvole::<Gf128, VSender<Gf128>, VReceiver<Gf128>>(rows, cols, d, weight);
        test_lpnvole::<Fp, VSender<Fp>, VReceiver<Fp>>(rows, cols, d, weight);
        test_lpnvole::<F61p, VSender<F61p>, VReceiver<F61p>>(rows, cols, d, weight);
    }*/
}
