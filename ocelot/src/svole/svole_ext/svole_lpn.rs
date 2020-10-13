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
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField, AbstractChannel};
use std::marker::PhantomData;

/// LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FiniteField, SV: SVoleSender, SPS: SpsVoleSender> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    rows: usize,
    cols: usize,
    u: Vec<FE::PrimeField>,
    w: Vec<FE>,
    //matrix_seed: Block, // matrix: Vec<Vec<FE::PrimeField>>,
    d: usize,
}
/// LpnsVole receiver.
pub struct Receiver<FE: FiniteField, SV: SVoleReceiver, SPS: SpsVoleReceiver> {
    _sv: PhantomData<SV>,
    spvole: SPS,
    delta: FE,
    rows: usize,
    cols: usize,
    v: Vec<FE>,
    //matrix_seed: Block, // matrix: Vec<Vec<FE::PrimeField>>,
    d: usize,
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
        let mut svole = SV::init(channel, rng)?;
        let uw = svole.send(channel, rows, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        //let matrix_seed = rand::random::<Block>();
        //let mut mat_rng = AesRng::from_seed(matrix_seed);
        //let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);
        //channel.write_block(&matrix_seed)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spvole = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole,
            rows,
            cols,
            u,
            w,
            //matrix_seed, // matrix,
            d,
        })
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        if self.cols % weight != 0 {
            return Err(Error::Other(
                "The hamming weight of the error vector doesn't divide the error vector length `e`"
                    .to_string(),
            ));
        }
        let m = self.cols / weight;
        let mut es = vec![];
        let mut ts = vec![];
        for _ in 0..weight {
            let ac = self.spvole.send(channel, m, rng)?;
            es.extend(ac.iter().map(|(a, _)| a));
            ts.extend(ac.iter().map(|(_, c)| c));
        }
        //println!("es={:?}", es);
        //println!("ts={:?}", ts);
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        let xs: Vec<FE::PrimeField> = indices
            .iter()
            .zip(es.into_iter())
            .map(|(ds, e)| {
                ds.into_iter()
                    .fold(FE::PrimeField::ZERO, |acc, (i, a)| acc + self.u[*i] * *a)
                    + e
            })
            .collect();
        debug_assert!(xs.len() == self.cols);
        let zs: Vec<FE> = indices
            .into_iter()
            .zip(ts.into_iter())
            .map(|(ds, t)| {
                ds.into_iter().fold(FE::ZERO, |acc, (i, a)| {
                    acc + self.w[i].multiply_by_prime_subfield(a)
                }) + t
            })
            .collect();
        for i in 0..self.rows {
            self.u[i] = xs[i];
            self.w[i] = zs[i];
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
        let mut svole = SV::init(channel, rng)?;
        let v = svole.receive(channel, rows, rng)?;
        let delta = svole.delta();
        //let matrix_seed = channel.read_block()?;
        /*let mut mat_rng = AesRng::from_seed(matrix_seed);
        let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);*/
        let spvole = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole,
            delta,
            rows,
            cols,
            v,
            //matrix_seed, //matrix,
            d,
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
        if self.cols % weight != 0 {
            return Err(Error::Other(
                "The hamming weight of the error vector doesn't divide the error vector length `e`"
                    .to_string(),
            ));
        }
        let m = self.cols / weight;
        let mut ss = vec![];
        for _ in 0..weight {
            let bs = self.spvole.receive(channel, m, rng)?;
            ss.extend(bs.iter());
        }
        //println!("ss={:?}", ss);
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        let ys: Vec<FE> = indices
            .into_iter()
            .zip(ss.into_iter())
            .map(|(ds, s)| {
                ds.into_iter().fold(FE::ZERO, |acc, (i, e)| {
                    acc + self.v[i].multiply_by_prime_subfield(e)
                }) + s
            })
            .collect();
        debug_assert!(ys.len() == self.cols);
        for i in 0..self.rows {
            self.v[i] = ys[i];
        }
        let output: Vec<FE> = ys.into_iter().skip(self.rows).collect();
        debug_assert!(output.len() == self.cols - self.rows);
        Ok(output)
    }
}
