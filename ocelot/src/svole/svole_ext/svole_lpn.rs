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
        utils::dot_product_with_lpn_mtx,
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
        let mut svole_sender = SV::init(channel, rng)?;
        let uw = svole_sender.send(channel, rows, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        //let matrix_seed = rand::random::<Block>();
        //let mut mat_rng = AesRng::from_seed(matrix_seed);
        //let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);
        //channel.write_block(&matrix_seed)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let spvole_sender = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole: spvole_sender,
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
        let len = self.cols - self.rows;
        let mut e = vec![FE::PrimeField::ZERO; self.cols];
        let mut t = vec![FE::ZERO; self.cols];
        for _i in 0..weight {
            let ac = self.spvole.send(channel, m, rng)?;
            let a: Vec<FE::PrimeField> = ac.iter().map(|&ac| ac.0).collect();
            let c: Vec<FE> = ac.iter().map(|&ac| ac.1).collect();
            e = [e, a].concat();
            t = [t, c].concat();
        }
        let mut x: Vec<FE::PrimeField> = (0..self.cols)
            .map(|i| dot_product_with_lpn_mtx::<FE::PrimeField>(i, self.rows, self.d, &self.u)) //dot_product(self.u.iter(), a[i].iter()))
            .collect();
        x = x.iter().zip(e.iter()).map(|(&x, &e)| x + e).collect();
        debug_assert!(x.len() == self.cols);
        let mut z: Vec<FE> = (0..self.cols)
            .map(|i| dot_product_with_lpn_mtx::<FE>(i, self.rows, self.d, &self.w)) //dot_product_with_subfield(&a[i], &self.w))
            .collect();
        z = z.iter().zip(t.iter()).map(|(&z, &t)| z + t).collect();
        for i in 0..self.rows {
            self.u[i] = x[i];
            self.w[i] = z[i];
        }
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
        //let matrix_seed = channel.read_block()?;
        /*let mut mat_rng = AesRng::from_seed(matrix_seed);
        let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);*/
        let spvole_receiver = SPS::init(channel, rng)?;
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole: spvole_receiver,
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
        let mut s = vec![FE::ZERO; self.cols];
        for _i in 0..weight {
            let b = self.spvole.receive(channel, m, rng)?;
            s = [s, b].concat();
        }
        let mut y: Vec<FE> = (0..self.cols)
            .map(|i| dot_product_with_lpn_mtx::<FE>(i, self.rows, self.d, &self.v)) //dot_product_with_subfield(&self.matrix[i], &self.v))
            .collect();
        y = y.iter().zip(s.iter()).map(|(&y, &s)| y + s).collect();
        debug_assert!(y.len() == self.cols);
        let output = y.iter().take(self.cols - self.rows).copied().collect();
        Ok(output)
    }
}
