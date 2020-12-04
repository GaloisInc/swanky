// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! LPN based Subfield Vector Oblivious Linear-function Evaluation (sVole)
//!
//! This module provides implementations of LPN sVole Traits.

// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! LPN based Subfield Vector Oblivious Linear-function Evaluation (sVole)
//!
//! This module provides implementations of LPN sVole Traits.

use crate::{
    errors::Error,
    svole::{
        base_svole::{BaseReceiver, BaseSender},
        svole_ext::{
            sp_svole::{SpsReceiver, SpsSender},
            LpnsVoleReceiver,
            LpnsVoleSender,
        },
    },
};
use generic_array::typenum::Unsigned;
use rand::Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};

/// Secure LPN parameters presented in (cf.
/// <https://eprint.iacr.org/2020/925>, Table 2).

/// LPN parameters for setup phase.
struct LpnSetupParams;

impl LpnSetupParams {
    /// Exponant which represent the depth of the GGM tree.
    const EXP: usize = 8;
    /// Hamming weight of the error vector `e` used in LPN assumption.
    const WEIGHT: usize = 2508;
    /// Number of columns `n` in the LPN matrix.
    const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 642048
    /// Number of rows `k` in the LPN matrix.
    const ROWS: usize = 19870;
}

/// LPN parameters for extend phase.
struct LpnExtendParams;

impl LpnExtendParams {
    /// Exponant which represent the depth of the GGM tree.
    const EXP: usize = 13;
    /// Hamming weight of the error vector `e` used in LPN assumption.
    const WEIGHT: usize = 1319;
    /// Number of columns `n` in the LPN matrix.
    const COLS: usize = (1 << Self::EXP) * Self::WEIGHT; // 10,805,248
    /// Number of rows `k` in the LPN matrix.
    const ROWS: usize = 589_760;
}

/// Small constant `d` used in the `liner codes` useful in acheiving efficient matrix multiplication.
const LPN_PARAMS_D: usize = 10;

fn lpn_mtx_indices<FE: FiniteField>(
    _col_idx: usize,
    rows: usize,
    rng: &mut AesRng,
) -> [(usize, FE::PrimeField); LPN_PARAMS_D] {
    let mut indices = [(0usize, FE::PrimeField::ONE); LPN_PARAMS_D];
    for i in 0..LPN_PARAMS_D {
        let mut rand_idx = rng.gen_range(0, rows);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = rng.gen_range(0, rows);
        }
        indices[i].0 = rand_idx as usize;
        if FE::PrimeField::MODULUS != 2 {
            let rand_elt: FE::PrimeField =
                FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(rng.gen::<Block>()));
            indices[i].1 = rand_elt;
        }
    }
    indices
}

/// LpnsVole sender.
pub struct Sender<FE: FiniteField> {
    spsvole: SpsSender<FE>,
    rows: usize,
    cols: usize,
    weight: usize,
    base_voles: Vec<(FE::PrimeField, FE)>,
    r: usize,
}
/// LpnsVole receiver.
pub struct Receiver<FE: FiniteField> {
    spsvole: SpsReceiver<FE>,
    delta: FE,
    rows: usize,
    cols: usize,
    weight: usize,
    base_voles: Vec<FE>,
    r: usize,
}

impl<FE: FiniteField> LpnsVoleSender for Sender<FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if cols % 2 != 0 {
            return Err(Error::InvalidColumns);
        }
        if rows >= cols {
            return Err(Error::InvalidRows);
        }
        if d >= rows {
            return Err(Error::InvalidD);
        }
        let pows = crate::svole::utils::gen_pows();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut svole = BaseSender::<FE>::init(channel, &pows, rng)?;
        let base_voles = svole.send(channel, rows + weight + r, rng)?;
        let spsvole = SpsSender::<FE>::init(channel, pows, weight, rng)?;
        debug_assert!(base_voles.len() == rows + weight + r);
        Ok(Self {
            spsvole,
            rows,
            cols,
            base_voles,
            weight,
            r,
        })
    }

    fn init_with_optimized_base_vole_gen<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows = crate::svole::utils::gen_pows();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        // Base voles are computed efficiently using smaller LPN parameters.
        let mut lpn_sender = Self::init(
            channel,
            LpnSetupParams::ROWS,
            LpnSetupParams::COLS,
            LPN_PARAMS_D,
            LpnSetupParams::WEIGHT,
            rng,
        )?;
        let base_voles = lpn_sender.send(channel, rng)?;
        // Since lpn_voles are having length more than the `K+T+r` so consider all of these are as optimized base voles.
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spsvole = SpsSender::<FE>::init(channel, pows, LpnExtendParams::WEIGHT, rng)?;
        Ok(Self {
            spsvole,
            rows: LpnExtendParams::ROWS,
            cols: LpnExtendParams::COLS,
            base_voles,
            weight: LpnExtendParams::WEIGHT,
            r,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        if self.cols % self.weight != 0 {
            return Err(Error::InvalidWeight);
        }
        debug_assert!(self.base_voles.len() >= self.rows + self.weight + self.r);
        let m = self.cols / self.weight;
        let uws = self.spsvole.send(
            channel,
            m,
            &self.base_voles[self.rows..self.rows + self.weight],
            rng,
        )?;
        self.spsvole.send_batch_consistency_check(
            channel,
            m,
            &uws,
            &self.base_voles[self.rows + self.weight..],
            rng,
        )?;
        let seed = rng.gen::<Block>();
        let mut lpn_rng = AesRng::from_seed(seed);
        channel.write_block(&seed)?;
        channel.flush()?;
        let indices: Vec<[(usize, FE::PrimeField); 10]> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, &mut lpn_rng))
            .collect();
        let xs: Vec<FE::PrimeField> = indices
            .iter()
            .zip(uws.iter().flatten())
            .map(|(ds, (e, _))| {
                ds.iter().fold(FE::PrimeField::ZERO, |acc, (i, a)| {
                    acc + self.base_voles[*i].0 * *a
                }) + *e
            })
            .collect();
        let zs: Vec<FE> = indices
            .into_iter()
            .zip(uws.into_iter().flatten())
            .map(|(ds, (_, t))| {
                ds.iter().fold(FE::ZERO, |acc, (i, a)| {
                    acc + self.base_voles[*i].1.multiply_by_prime_subfield(*a)
                }) + t
            })
            .collect();
        let nb = self.rows + self.weight + self.r;
        for i in 0..nb {
            self.base_voles[i] = (xs[i], zs[i]);
        }
        let lpn_voles: Vec<(FE::PrimeField, FE)> = xs
            .into_iter()
            .skip(nb)
            .zip(zs.into_iter().skip(nb))
            .collect();
        debug_assert!(lpn_voles.len() == self.cols - nb);
        Ok(lpn_voles)
    }
}

impl<FE: FiniteField> LpnsVoleReceiver for Receiver<FE> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if cols % 2 != 0 {
            return Err(Error::InvalidColumns);
        }
        if rows >= cols {
            return Err(Error::InvalidRows);
        }
        if d >= rows {
            return Err(Error::InvalidD);
        }
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let pows = crate::svole::utils::gen_pows();
        let mut svole = BaseReceiver::<FE>::init(channel, &pows, rng)?;
        let base_voles = svole.receive(channel, rows + weight + r, rng)?;
        let delta = svole.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, weight, rng)?;
        debug_assert!(base_voles.len() == rows + weight + r);
        Ok(Self {
            spsvole,
            delta,
            rows,
            cols,
            base_voles,
            weight,
            r,
        })
    }

    fn init_with_optimized_base_vole_gen<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows = crate::svole::utils::gen_pows();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut svole = Self::init(
            channel,
            LpnSetupParams::ROWS,
            LpnSetupParams::COLS,
            LPN_PARAMS_D,
            LpnSetupParams::WEIGHT,
            rng,
        )?;
        let lpn_voles = svole.receive(channel, rng)?;
        let delta = svole.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, LpnExtendParams::WEIGHT, rng)?;
        Ok(Self {
            spsvole,
            delta,
            rows: LpnExtendParams::ROWS,
            cols: LpnExtendParams::COLS,
            base_voles: lpn_voles,
            weight: LpnExtendParams::WEIGHT,
            r,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        if self.cols % self.weight != 0 {
            return Err(Error::InvalidWeight);
        }
        let m = self.cols / self.weight;
        let vs = self.spsvole.receive(
            channel,
            m,
            &self.base_voles[self.rows..self.rows + self.weight],
            rng,
        )?;
        self.spsvole.receive_batch_consistency_check(
            channel,
            m,
            &vs,
            &self.base_voles[self.rows + self.weight..],
            rng,
        )?;
        let seed = channel.read_block()?;
        let mut lpn_rng = AesRng::from_seed(seed);
        let ys: Vec<FE> = vs
            .iter()
            .flatten()
            .enumerate()
            .map(|(i, s)| {
                lpn_mtx_indices::<FE>(i, self.rows, &mut lpn_rng)
                    .iter()
                    .fold(FE::ZERO, |acc, (j, e)| {
                        acc + self.base_voles[*j].multiply_by_prime_subfield(*e)
                    })
                    + *s
            })
            .collect();
        debug_assert!(ys.len() == self.cols);
        let nb = self.rows + self.weight + self.r;
        for (i, item) in ys.iter().enumerate().take(nb) {
            self.base_voles[i] = *item;
        }
        let lpn_voles: Vec<FE> = ys.into_iter().skip(nb).collect();
        debug_assert!(lpn_voles.len() == self.cols - nb);
        Ok(lpn_voles)
    }
}

#[cfg(test)]
mod tests {
    use crate::svole::svole_ext::{
        svole_lpn::{
            LpnExtendParams,
            LpnSetupParams,
            Receiver as LpnVoleReceiver,
            Sender as LpnVoleSender,
        },
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
        let d = 10; // can't access LPN_PARAMS_D;
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
