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
        svole_utils::{dot_product, to_fpr_vec},
        SVoleReceiver,
        SVoleSender,
    },
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// A LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FF, SV: SVoleSender, SPS: SpsVoleSender> {
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
    svole: SV,
    spsvole: SPS,
    delta: FE,
    rows: usize,
    cols: usize,
    v: Vec<FE>,
    matrix: Vec<Vec<FE::PrimeField>>,
}

/// Code generator G that outputs matrix A for the given dimension `k` by `n`.
pub fn code_gen<FE: FF, RNG: CryptoRng + RngCore>(
    rows: usize,
    cols: usize,
    d: usize,
    rng: &mut RNG,
) -> Vec<Vec<FE>> {
    let mut res: Vec<Vec<FE>> = vec![vec![FE::ZERO; cols]; rows];
    let g = FE::GENERATOR;
    for i in 0..cols {
        for _j in 0..d {
            let mut rand_ind = rng.gen_range(0, rows);
            while res[rand_ind][i] != FE::ZERO {
                rand_ind = rng.gen_range(0, cols);
            }
            let nz_elt = g;
            let fe = nz_elt.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
            res[rand_ind][i] = fe;
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
        if rows % 2 != 0 {
            return Err(Error::Other(
                "The number of rows of the LPN matrix is not multiple of 2!".to_string(),
            ));
        }
        if (rows >= cols) | (d >= cols) {
            return Err(Error::Other("Either the number of rows or constant d used in the LPN matrix construction
            is greater than the number of columns. Please make sure these values less than the no. of columns!".to_string()));
        }
        println!("Hello");
        let mut svole_sender = SV::init(channel, rng).unwrap();
        println!("Hello after");
        let k = rows;
        let n = cols;
        let uw = svole_sender.send(channel, k, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        let sp_svole_sender = SPS::init(channel, rng)?;
        let matrix = code_gen::<FE::PrimeField, _>(k, n, d, rng);
        println!("matrix={:?}", matrix);
        for i in 0..k {
            for j in 0..n {
                channel.write_fe::<FE::PrimeField>(matrix[i][j])?;
            }
        }
        channel.flush()?;
        Ok(Self {
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
        if weight >= self.cols {
            return Err(Error::Other(
                "The hamming weight of the error vector is greater than or equal 
            to the length of the error vector `e`"
                    .to_string(),
            ));
        }
        let m = self.cols / weight;
        let ac = self.spsvole.send(channel, m as u128, rng)?;
        let mut e = vec![FE::PrimeField::ZERO; self.cols];
        let mut t = vec![FE::ZERO; self.cols];
        // Sample error vector `e` with hamming weight `t`
        for i in 0..weight {
            let ind = rng.gen_range(0, weight);
            e[i * weight + ind] = FE::PrimeField::ONE;
        }
        for i in 0..weight {
            let ind = rng.gen_range(0, weight);
            t[i * weight + ind] = FE::ONE;
        }
        let a = &self.matrix;
        let mut x: Vec<FE::PrimeField> = (0..self.rows)
            .map(|i| dot_product(&self.u, &a[i]))
            .collect();
        x = x.iter().zip(e.iter()).map(|(&x_, &e_)| x_ + e_).collect();
        let mut z: Vec<FE> = (0..self.rows)
            .map(|i| dot_product::<FE>(&self.w, &to_fpr_vec(&a[i])))
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
        if rows % 2 != 0 {
            return Err(Error::Other(
                "The number of rows of the LPN matrix is not multiple of 2!".to_string(),
            ));
        }
        if (rows >= cols) | (d >= cols) {
            return Err(Error::Other("Either the number of rows or constant d used in the LPN matrix construction
            is greater than the number of columns. Please make sure these values less than the no. of columns!".to_string()));
        }
        let mut svole_receiver = SV::init(channel, rng)?;
        let v = svole_receiver.receive(channel, rows, rng)?;
        let sp_svole_receiver = SPS::init(channel, rng)?;
        let delta = FE::random(rng);
        let mut matrix: Vec<Vec<FE::PrimeField>> = vec![vec![FE::PrimeField::ZERO; cols]; rows];
        for i in 0..rows {
            for j in 0..cols {
                matrix[i][j] = channel.read_fe::<FE::PrimeField>()?;
            }
        }
        println!("matrix={:?}", matrix);
        Ok(Self {
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
        let mut s = vec![FE::ZERO; self.cols];
        // define the vectors e and t.
        for _i in 0..weight {
            let rand_ind = rng.gen_range(0, weight);
            s[rand_ind] = FE::ONE;
        }
        let mut y: Vec<FE> = (0..self.rows)
            .map(|i| dot_product(&self.v, &to_fpr_vec(&self.matrix[i])))
            .collect();
        y = y.iter().zip(s.iter()).map(|(&y, &s)| y + s).collect();
        let output = (self.rows..self.cols).map(|i| y[i]).collect();
        Ok(output)
    }
}
