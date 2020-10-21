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
        svole_ext::{LpnsVoleReceiver, LpnsVoleSender, SpsVoleReceiver, SpsVoleSender},
        utils::lpn_mtx_indices,
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField, AbstractChannel};
use std::marker::PhantomData;

/// LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FiniteField, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender<SV, Msg = FE>> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    rows: usize,
    cols: usize,
    uws: Vec<(FE::PrimeField, FE)>,
    d: usize,
    weight: usize,
}
/// LpnsVole receiver.
pub struct Receiver<
    FE: FiniteField,
    SV: SVoleReceiver<Msg = FE>,
    SPS: SpsVoleReceiver<SV, Msg = FE>,
> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    delta: FE,
    rows: usize,
    cols: usize,
    vs: Vec<FE>,
    d: usize,
    weight: usize,
}

impl<FE: FiniteField, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender<SV, Msg = FE>> LpnsVoleSender
    for Sender<FE, SV, SPS>
{
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
        let mut svole = SV::init(channel, rng)?;
        let mut uws = svole.send(channel, rows, rng)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spvole = SPS::init(channel, rng, &mut svole, weight)?;
        uws.extend(spvole.voles());
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        debug_assert!(uws.len() == rows + weight + r);
        Ok(Self {
            _sv: PhantomData::<SV>,
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
        let mut es = vec![];
        let mut ts = vec![];
        let mut uws = vec![vec![]];
        for _ in 0..self.weight {
            let ac = self.spvole.send(channel, m, rng)?;
            es.extend(ac.iter().map(|(a, _)| a));
            ts.extend(ac.iter().map(|(_, c)| c));
            uws.push(ac);
        }
        debug_assert!(es.len() == self.cols);
        debug_assert!(ts.len() == self.cols);
        //consistency check
        self.spvole
            .send_batch_consistency_check(channel, m, uws, rng)?;
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        let us: Vec<FE::PrimeField> = self.uws.iter().map(|(u, _)| *u).collect();
        let ws: Vec<FE> = self.uws.iter().map(|(_, w)| *w).collect();
        let xs: Vec<FE::PrimeField> = indices
            .iter()
            .zip(es.into_iter())
            .map(|(ds, e)| {
                ds.into_iter()
                    .fold(FE::PrimeField::ZERO, |acc, (i, a)| acc + us[*i] * *a)
                    + e
            })
            .collect();
        debug_assert!(xs.len() == self.cols);
        let zs: Vec<FE> = indices
            .into_iter()
            .zip(ts.into_iter())
            .map(|(ds, t)| {
                ds.into_iter().fold(FE::ZERO, |acc, (i, a)| {
                    acc + ws[i].multiply_by_prime_subfield(a)
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

impl<FE: FiniteField, SV: SVoleReceiver<Msg = FE>, SPS: SpsVoleReceiver<SV, Msg = FE>>
    LpnsVoleReceiver for Receiver<FE, SV, SPS>
{
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
        let mut svole = SV::init(channel, rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut vs = svole.receive(channel, rows, rng)?;
        let svole_delta = svole.delta();
        let spvole = SPS::init(channel, rng, &mut svole, weight)?;
        let spvole_delta = spvole.delta();
        vs.extend(spvole.voles());
        debug_assert!(spvole_delta == svole_delta);
        debug_assert!(vs.len() == rows + weight + r);
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole,
            delta: spvole_delta,
            rows: rows + weight + r,
            cols,
            vs,
            d,
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
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        let ys: Vec<FE> = indices
            .into_iter()
            .zip(ss.into_iter())
            .map(|(ds, s)| {
                ds.into_iter().fold(FE::ZERO, |acc, (i, e)| {
                    acc + self.vs[i].multiply_by_prime_subfield(e)
                }) + s
            })
            .collect();
        debug_assert!(ys.len() == self.cols);
        for i in 0..self.rows {
            self.vs[i] = ys[i];
        }
        let output: Vec<FE> = ys.into_iter().skip(self.rows).collect();
        debug_assert!(output.len() == self.cols - self.rows);
        Ok(output)
    }
}
