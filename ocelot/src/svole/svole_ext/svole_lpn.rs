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
        svole_ext::sp_svole::{SpsReceiver, SpsSender},
        svole_ext::{LpnsVoleReceiver, LpnsVoleSender},
        utils::lpn_mtx_indices,
    },
};
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField, AbstractChannel};

/// LpnsVole sender.
pub struct Sender<FE: FiniteField> {
    spvole: SpsSender<FE>,
    rows: usize,
    cols: usize,
    uws: Vec<(FE::PrimeField, FE)>,
    d: usize,
    weight: usize,
}
/// LpnsVole receiver.
pub struct Receiver<FE: FiniteField> {
    spvole: SpsReceiver<FE>,
    delta: FE,
    rows: usize,
    cols: usize,
    vs: Vec<FE>,
    weight: usize,
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
        let mut svole = BaseSender::<FE>::init(channel, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let uws = svole.send(channel, rows + weight + r, rng)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spvole = SpsSender::<FE>::init(channel, &uws[rows..], weight, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        debug_assert!(uws.len() == rows + weight + r);
        Ok(Self {
            spvole,
            rows: rows + weight + r,
            cols,
            uws,
            d,
            weight,
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
        let mut ets = vec![];
        let mut uws = vec![vec![]];
        for _ in 0..self.weight {
            let ac = self.spvole.send(channel, m, rng)?;
            // XXX remove this extra clone.
            ets.extend(ac.clone());
            uws.push(ac);
        }
        debug_assert!(ets.len() == self.cols);
        self.spvole
            .send_batch_consistency_check(channel, m, uws, rng)?;
        let indices: Vec<[(usize, FE::PrimeField); 10]> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows))
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
        debug_assert!(xs.len() == self.cols);
        let zs: Vec<FE> = indices
            .into_iter()
            .zip(ets.into_iter())
            .map(|(ds, (_, t))| {
                ds.iter().fold(FE::ZERO, |acc, (i, a)| {
                    acc + self.uws[*i].1.multiply_by_prime_subfield(*a)
                }) + t
            })
            .collect();
        for i in 0..self.rows {
            self.uws[i] = (xs[i], zs[i]);
        }
        let output: Vec<(FE::PrimeField, FE)> = xs
            .into_iter()
            .skip(self.rows)
            .zip(zs.into_iter().skip(self.rows))
            .collect();
        debug_assert!(output.len() == self.cols - self.rows);
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
        let mut svole = BaseReceiver::<FE>::init(channel, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let vs = svole.receive(channel, rows + weight + r, rng)?;
        let delta = svole.delta();
        let spvole = SpsReceiver::<FE>::init(channel, &vs[rows..], delta, weight, rng)?;
        debug_assert!(vs.len() == rows + weight + r);
        Ok(Self {
            spvole,
            delta,
            rows: rows + weight + r,
            cols,
            vs,
            weight,
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
        let mut vs = vec![vec![]];
        for _ in 0..self.weight {
            let bs = self.spvole.receive(channel, m, rng)?;
            ss.extend(bs.iter());
            vs.push(bs);
        }
        self.spvole
            .receive_batch_consistency_check(channel, m, vs, rng)?;
        debug_assert!(ss.len() == self.cols);
        let ys: Vec<FE> = (0..self.cols)
            .map(|i| {
                lpn_mtx_indices::<FE>(i, self.rows)
                    .iter()
                    .fold(FE::ZERO, |acc, (j, e)| {
                        acc + self.vs[*j].multiply_by_prime_subfield(*e)
                    })
                    + ss[i]
            })
            .collect();
        debug_assert!(ys.len() == self.cols);
        for (i, item) in ys.iter().enumerate().take(self.rows) {
            self.vs[i] = *item;
        }
        let output: Vec<FE> = ys.into_iter().skip(self.rows).collect();
        debug_assert!(output.len() == self.cols - self.rows);
        Ok(output)
    }
}
