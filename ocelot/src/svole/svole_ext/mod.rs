// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licfensing information.

//! Single-point Subfield Vector Oblivious Linear Evaluation (SpsVOLE) and
//! LPN based Subfield Vector Oblivious Linear Evaluation (SVOLE) traits.

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
    /// Runs any one-time initialization with secure LPN parameters, k (rows), n (cols), t (weight), and a constant `d`
    /// used in `d-linear` codes. Also note the fact that `rows < cols` and `d < cols`.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// This procedure can be run multiple times by passing base voles of length `k + t + r` and produces `n` number of lpn voles among which
    /// `k + t + r` voles can be used as base voles to the next iteration and the remaining ones are usable voles. Of course, all of the voles
    /// satisfies the vole correlation,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        base_uws: &[(<Self::Msg as FF>::PrimeField, Self::Msg)],
        rng: &mut RNG,
    ) -> Result<
        (
            Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>,
            Vec<(<Self::Msg as FF>::PrimeField, Self::Msg)>,
        ),
        Error,
    >;
}

/// A trait for LpnsVole Sender.
pub trait LpnsVoleReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays, and implements Finite Field trait.
    type Msg: FF;
    /// Runs any one-time initialization with secure LPN parameters, `k (rows)`, `n (cols)`, `t (weight)`, and a constant `d`
    /// used in `d-linear` codes. Also note the fact that `rows < cols` and `d < cols`.
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        delta: Self::Msg,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Returns the receiver's choice during the OT call.
    fn delta(&self) -> Self::Msg;
    /// This procedure can be run multiple times by passing base voles of length `k + t + r` and produces `n` number of lpn voles among which
    /// `k + t + r` voles can be used as base voles to the next iteration and the remaining ones are usable voles. Of course, all of the voles
    /// satisfies the vole correlation,
    /// i.e, outputs `u` and `w` such that `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`.
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        base_vs: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<(Vec<Self::Msg>, Vec<Self::Msg>), Error>;
}

#[cfg(test)]
mod tests {
    use crate::svole::{
        base_svole::{BaseReceiver, BaseSender},
        svole_ext::{
            lpn_params::{LpnExtendParams, LpnSetupParams},
            svole_lpn::{Receiver as LpnVoleReceiver, Sender as LpnVoleSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
    };
    use generic_array::typenum::Unsigned;
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
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        debug_assert!(cols % weight == 0);
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = crate::svole::utils::gen_pows();
            let mut base_vole = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            let base_uws = base_vole
                .send(&mut channel, rows + weight + r, &mut rng)
                .unwrap();
            let mut vole = VSender::init(&mut channel, rows, cols, d, weight, &mut rng).unwrap();
            vole.send(&mut channel, &base_uws, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = crate::svole::utils::gen_pows();
        let mut base_vole = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let base_vs = base_vole
            .receive(&mut channel, rows + weight + r, &mut rng)
            .unwrap();
        let delta = base_vole.delta();
        let mut vole =
            VReceiver::init(&mut channel, rows, cols, d, weight, delta, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, &base_vs, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..weight as usize {
            // Testing base voles required for the next iteration
            let right0 = vole.delta().multiply_by_prime_subfield((uws.0)[i].0) + (vs.0)[i];
            assert_eq!((uws.0)[i].1, right0);
            // Testing usable LPN voles
            let right1 = vole.delta().multiply_by_prime_subfield((uws.1)[i].0) + (vs.1)[i];
            assert_eq!((uws.1)[i].1, right1);
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
    /*#[test]
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
