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
            LpnsVoleReceiver, LpnsVoleSender,
        },
    },
};
use generic_array::typenum::Unsigned;
use rand::Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};

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
    uws: Vec<(FE::PrimeField, FE)>,
    weight: usize,
    r: usize,
}
/// LpnsVole receiver.
pub struct Receiver<FE: FiniteField> {
    spsvole: SpsReceiver<FE>,
    delta: FE,
    rows: usize,
    cols: usize,
    vs: Vec<FE>,
    weight: usize,
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
        let mut svole = BaseSender::<FE>::init(channel, &pows, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let uws = svole.send(channel, rows + weight + r, rng)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spsvole = SpsSender::<FE>::init(channel, pows, weight, rng)?;
        debug_assert!(uws.len() == rows + weight + r);
        Ok(Self {
            spsvole,
            rows,
            cols,
            uws,
            weight,
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
        let m = self.cols / self.weight;
        let mut ets = Vec::with_capacity(self.cols);
        let mut uws = vec![];
        for i in 0..self.weight {
            let ac = self
                .spsvole
                .send(channel, m, &self.uws[self.rows + i], rng)?;
            ets.extend(ac.iter());
            uws.push(ac);
        }
        debug_assert!(ets.len() == self.cols);
        self.spsvole.send_batch_consistency_check(
            channel,
            m,
            &uws,
            &self.uws[self.rows + self.weight..],
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
            .zip(ets.iter())
            .map(|(ds, (e, _))| {
                ds.iter().fold(FE::PrimeField::ZERO, |acc, (i, a)| {
                    acc + self.uws[*i].0 * *a
                }) + *e
            })
            .collect();
        let zs: Vec<FE> = indices
            .into_iter()
            .zip(ets.into_iter())
            .map(|(ds, (_, t))| {
                ds.iter().fold(FE::ZERO, |acc, (i, a)| {
                    acc + self.uws[*i].1.multiply_by_prime_subfield(*a)
                }) + t
            })
            .collect();
        let nb = self.rows + self.weight + self.r;
        for i in 0..nb {
            self.uws[i] = (xs[i], zs[i]);
        }
        let output: Vec<(FE::PrimeField, FE)> = xs
            .into_iter()
            .skip(nb)
            .zip(zs.into_iter().skip(nb))
            .collect();
        debug_assert!(output.len() == self.cols - nb);
        Ok(output)
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
        let pows = crate::svole::utils::gen_pows();
        let mut svole = BaseReceiver::<FE>::init(channel, &pows, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let vs = svole.receive(channel, rows + weight + r, rng)?;
        let delta = svole.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, weight, rng)?;
        debug_assert!(vs.len() == rows + weight + r);
        Ok(Self {
            spsvole,
            delta,
            rows,
            cols,
            vs,
            weight,
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
        let mut ss = vec![];
        let mut vs = vec![];
        for i in 0..self.weight {
            let bs = self
                .spsvole
                .receive(channel, m, &self.vs[self.rows + i], rng)?;
            ss.extend(bs.iter());
            vs.push(bs);
        }
        self.spsvole.receive_batch_consistency_check(
            channel,
            m,
            vs,
            &self.vs[self.rows + self.weight..],
            rng,
        )?;
        debug_assert!(ss.len() == self.cols);
        let seed = channel.read_block()?;
        let mut lpn_rng = AesRng::from_seed(seed);
        let ys: Vec<FE> = (0..self.cols)
            .map(|i| {
                lpn_mtx_indices::<FE>(i, self.rows, &mut lpn_rng)
                    .iter()
                    .fold(FE::ZERO, |acc, (j, e)| {
                        acc + self.vs[*j].multiply_by_prime_subfield(*e)
                    })
                    + ss[i]
            })
            .collect();
        debug_assert!(ys.len() == self.cols);
        let nb = self.rows + self.weight + self.r;
        for (i, item) in ys.iter().enumerate().take(nb) {
            self.vs[i] = *item;
        }
        let output: Vec<FE> = ys.into_iter().skip(nb).collect();
        debug_assert!(output.len() == self.cols - nb);
        Ok(output)
    }
}
