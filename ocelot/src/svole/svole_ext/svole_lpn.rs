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
        svole_utils::{dot_prod, to_fpr, to_fpr_vec},
        SVoleReceiver,
        SVoleSender,
    },
};
use rand::{Rng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel, AesRng, Block};
use std::marker::PhantomData;

/// A LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FF, SV: SVoleSender, SPS: SpsVoleSender> {
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _sps: PhantomData<SPS>,
    svole: SV,
    spsvole: SPS,
    rows: usize,
    cols: usize,
    u: Vec<FE::PrimeField>,
    w: Vec<FE>,
    matrix: Vec<Vec<FE::PrimeField>>,
}
/// A LpnsVole receiver.
pub struct Receiver<FE: FF, SV: SVoleReceiver, SPS: SpsVoleReceiver> {
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _sps: PhantomData<SPS>,
    svole: SV,
    spsvole: SPS,
    delta: FE,
    rows: usize,
    cols: usize,
    v: Vec<FE>,
    matrix: Vec<Vec<FE::PrimeField>>,
}

/// Code generator G that outputs matrix A for the given dimension `k` by `n`.
pub fn code_gen<FE: FF>(rows: usize, cols: usize, d: usize) -> Vec<Vec<FE>> {
    let seed = rand::random::<Block>();
    let mut rng = AesRng::from_seed(seed);
    let mut res: Vec<Vec<_>> = Vec::new();
    for i in 0..rows {
        for j in 0..cols {
            res[i][j] = FE::random(&mut rng);
        }
    }
    res
}

impl<FE: FF, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender> LpnsVoleSender for Sender<FE, SV, SPS> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut svole_sender = SV::init(channel, rng).unwrap();
        let k = rows;
        let n = cols;
        let uw = svole_sender.send(channel, k, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        let sp_svole_sender = SPS::init(channel, rng).unwrap();
        let matrix = code_gen(k, n, d);
        Ok(Self {
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _sps: PhantomData::<SPS>,
            svole: svole_sender,
            spsvole: sp_svole_sender,
            rows,
            cols,
            u,
            w,
            matrix,
        })
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let m = self.cols / weight;
        let ac = self.spsvole.send(channel, m as u128, rng).unwrap();
        let mut e = vec![FE::PrimeField::zero(); self.cols];
        let mut t = vec![FE::zero(); self.cols];
        // Sample error vector `e` with hamming weight `t`
        for i in 0..weight {
            let ind = rng.gen_range(0, weight);
            e[i * weight + ind] = FE::PrimeField::one();
        }
        for i in 0..weight {
            let ind = rng.gen_range(0, weight);
            t[i * weight + ind] = FE::one();
        }
        let a = &self.matrix;
        let mut x: Vec<FE::PrimeField> = (0..self.rows).map(|i| dot_prod(&self.u, &a[i])).collect();
        x = x.iter().zip(e.iter()).map(|(&x_, &e_)| x_ + e_).collect();
        let mut z: Vec<FE> = (0..self.rows)
            .map(|i| dot_prod::<FE>(&self.w, &to_fpr_vec(&a[i])))
            .collect();
        z = z.iter().zip(t.iter()).map(|(&z, &t)| z + t).collect();
        for i in 0..self.rows {
            self.u[i] = x[i];
            self.w[i] = z[i];
        }
        let output = (self.rows..self.cols).map(|i| (x[i], z[i])).collect();
        Ok(output)
    }
}

impl<FE: FF, SV: SVoleReceiver<Msg = FE>, SPS: SpsVoleReceiver> LpnsVoleReceiver
    for Receiver<FE, SV, SPS>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut svole_receiver = SV::init(channel, rng).unwrap();
        let v = svole_receiver.receive(channel, rows, rng)?;
        let sp_svole_receiver = SPS::init(channel, rng).unwrap();
        let delta = FE::random(rng);
        let matrix = code_gen(rows, cols, d);
        Ok(Self {
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _sps: PhantomData::<SPS>,
            svole: svole_receiver,
            spsvole: sp_svole_receiver,
            delta,
            rows,
            cols,
            v,
            matrix,
        })
    }
    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let m = self.cols / weight;
        let b = self.spsvole.receive(channel, m as u128, rng)?;
        let mut s = vec![FE::zero(); self.cols];
        // define the vectors e and t.
        for _i in 0..weight {
            let rand_ind = rng.gen_range(0, weight);
            s[rand_ind] = FE::one();
        }
        let mut y: Vec<FE> = (0..self.rows)
            .map(|i| dot_prod(&self.v, &to_fpr_vec(&self.matrix[i])))
            .collect();
        y = y.iter().zip(s.iter()).map(|(&y, &s)| y + s).collect();
        let output = (self.rows..self.cols).map(|i| y[i]).collect();
        Ok(output)
    }
}
