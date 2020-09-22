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
        svole_ext::{
            ggm_utils::dot_product,
            LpnsVoleReceiver,
            LpnsVoleSender,
            SpsVoleReceiver,
            SpsVoleSender,
        },
        utils::to_fpr_vec,
        SVoleReceiver,
        SVoleSender,
    },
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};
use std::marker::PhantomData;

/// A LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FiniteField, SV: SVoleSender, SPS: SpsVoleSender> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    rows: usize,
    cols: usize,
    u: Vec<FE::PrimeField>,
    w: Vec<FE>,
    matrix: Vec<Vec<FE::PrimeField>>,
}
/// A LpnsVole receiver.
pub struct Receiver<FE: FiniteField, SV: SVoleReceiver, SPS: SpsVoleReceiver> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    delta: FE,
    rows: usize,
    cols: usize,
    v: Vec<FE>,
    matrix: Vec<Vec<FE::PrimeField>>,
}

/// Code generator G that outputs matrix A for the given dimension `k` by `n`.
pub fn code_gen<FE: FiniteField>(rows: usize, cols: usize, d: usize, seed: Block) -> Vec<Vec<FE>> {
    let g = FE::GENERATOR;
    let mut rng = AesRng::from_seed(seed);
    let mut res: Vec<Vec<FE>> = vec![vec![FE::ZERO; cols]; rows];
    for i in 0..cols {
        for _j in 0..d {
            let mut rand_ind = rng.gen_range(0, rows);
            while (res[rand_ind])[i] != FE::ZERO {
                rand_ind = rng.gen_range(0, rows);
            }
            let nz_elt = g;
            let fe = nz_elt.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
            (res[rand_ind])[i] = fe;
        }
    }
    res
}

impl<FE: FiniteField, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender<Msg = FE>> LpnsVoleSender
    for Sender<FE, SV, SPS>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        d: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if cols % 2 != 0 {
            return Err(Error::Other(
                "The number of columns of the LPN matrix is not multiple of 2!".to_string(),
            ));
        }
        if (rows >= cols) | (d >= cols) {
            return Err(Error::Other("Either the number of rows or constant d used in the LPN matrix construction
            is greater than the number of columns. Please make sure these values less than the no. of columns!".to_string()));
        }
        let mut svole_sender = SV::init(channel, rng)?;
        let uw = svole_sender.send(channel, rows, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        let matrix_seed = rand::random::<Block>();
        let matrix = code_gen::<FE::PrimeField>(rows, cols, d, matrix_seed);
        channel.write_block(&matrix_seed)?;
        channel.flush()?;
        let spvole_sender = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole: spvole_sender,
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
        if weight >= self.cols {
            return Err(Error::Other(
                "The hamming weight of the error vector is greater than or equal 
            to the length of the error vector `e`"
                    .to_string(),
            ));
        }
        let m = self.cols / weight;
        let mut e = vec![FE::PrimeField::ZERO; self.cols];
        let mut t = vec![FE::ZERO; self.cols];
        for _i in 0..weight {
            let ac = self.spvole.send(channel, m as u128, rng)?;
            let (a, c) = ac.iter().cloned().unzip();
            e = [e, a].concat();
            t = [t, c].concat();
        }
        let a = &self.matrix;
        let mut x: Vec<FE::PrimeField> = (0..self.rows)
            .map(|i| dot_product(self.u.clone().into_iter(), a[i].clone().into_iter()))
            .collect();
        x = x.iter().zip(e.iter()).map(|(&x_, &e_)| x_ + e_).collect();
        let mut z: Vec<FE> = (0..self.rows)
            .map(|i| dot_product(self.w.clone().into_iter(), to_fpr_vec(&a[i]).into_iter()))
            .collect();
        z = z.iter().zip(t.iter()).map(|(&z, &t)| z + t).collect();
        for i in 0..self.rows {
            self.u[i] = x[i];
            self.w[i] = z[i];
        }
        let len = self.cols - self.rows;
        let output = (0..len).map(|i| (x[i], z[i])).collect();
        Ok(output)
    }
}

impl<FE: FiniteField, SV: SVoleReceiver<Msg = FE>, SPS: SpsVoleReceiver<Msg = FE>> LpnsVoleReceiver
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
        if cols % 2 != 0 {
            return Err(Error::Other(
                "The number of columns of the LPN matrix is not multiple of 2!".to_string(),
            ));
        }
        if (rows >= cols) | (d >= cols) {
            return Err(Error::Other("Either the number of rows or constant d used in the LPN matrix construction
            is greater than the number of columns. Please make sure these values less than the no. of columns!".to_string()));
        }
        let mut svole_receiver = SV::init(channel, rng)?;
        let v = svole_receiver.receive(channel, rows, rng)?;
        let delta = svole_receiver.delta();
        let matrix_seed = channel.read_block()?;
        let matrix = code_gen::<FE::PrimeField>(rows, cols, d, matrix_seed);
        let spvole_receiver = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole: spvole_receiver,
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
        let mut s = vec![FE::ZERO; self.cols];
        for _i in 0..weight {
            let b = self.spvole.receive(channel, m as u128, rng)?;
            s = [s, b].concat();
        }
        let mut y: Vec<FE> = (0..self.rows)
            .map(|i| {
                dot_product(
                    self.v.clone().into_iter(),
                    to_fpr_vec(&self.matrix[i]).into_iter(),
                )
            })
            .collect();
        y = y.iter().zip(s.iter()).map(|(&y, &s)| y + s).collect();
        let output = y.iter().take(self.cols - self.rows).copied().collect();
        Ok(output)
    }
}
