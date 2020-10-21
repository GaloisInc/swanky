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
pub struct Sender<FE: FiniteField, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender<SV, Msg = FE>> {
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
    v: Vec<FE>,
    //matrix_seed: Block, // matrix: Vec<Vec<FE::PrimeField>>,
    d: usize,
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
        let uw = svole.send(channel, rows, rng)?;
        // This flush statement is needed, otherwise, it hangs on.
        channel.flush()?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        //let matrix_seed = rand::random::<Block>();
        //let mut mat_rng = AesRng::from_seed(matrix_seed);
        //let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);
        //channel.write_block(&matrix_seed)?;
        let spvole = SPS::init(channel, rng, svole)?;
        //println!("u={:?}", u);
        //println!("w={:?}", w);
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
            return Err(Error::InvalidWeight);
        }
        let m = self.cols / weight;
        let mut es = vec![];
        let mut ts = vec![];
        let mut uws = vec![vec![]];
        for _ in 0..weight {
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
        //println!("es={:?}\n", es);
        //println!("ts={:?}\n", ts);
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        //println!("indices_sender={:?}", indices);
        let xs: Vec<FE::PrimeField> = indices
            .iter()
            .zip(es.into_iter())
            .map(|(ds, e)| {
                ds.into_iter()
                    .fold(FE::PrimeField::ZERO, |acc, (i, a)| acc + self.u[*i] * *a)
                    + e
            })
            .collect();
        //println!("xs={:?}", xs);
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
        //println!("zs={:?}", zs);
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

impl<FE: FiniteField, SV: SVoleReceiver<Msg = FE>, SPS: SpsVoleReceiver<SV, Msg = FE>>
    LpnsVoleReceiver for Receiver<FE, SV, SPS>
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
            return Err(Error::InvalidColumns);
        }
        if rows >= cols {
            return Err(Error::InvalidRows);
        }
        if d >= rows {
            return Err(Error::InvalidD);
        }
        let mut svole = SV::init(channel, rng)?;
        let v = svole.receive(channel, rows, rng)?;
        let svole_delta = svole.delta();
        //let matrix_seed = channel.read_block()?;
        /*let mut mat_rng = AesRng::from_seed(matrix_seed);
        let matrix = code_gen::<FE::PrimeField, _>(rows, cols, d, &mut mat_rng);*/
        let spvole = SPS::init(channel, rng, svole)?;
        //println!("v={:?}", v);
        let spvole_delta = spvole.delta();
        debug_assert!(spvole_delta == svole_delta);
        //println!("svole_delta = {:?}", svole_delta);
        //println!("sp_vole_delta = {:?}", spvole_delta);
        Ok(Self {
            _sv: PhantomData::<SV>,
            spvole,
            delta: spvole_delta,
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
            return Err(Error::InvalidWeight);
        }
        let m = self.cols / weight;
        let mut ss = vec![];
        let mut vs = vec![vec![]];
        for _ in 0..weight {
            let bs = self.spvole.receive(channel, m, rng)?;
            ss.extend(bs.iter());
            vs.push(bs);
        }
        self.spvole
            .receive_batch_consistency_check(channel, m, vs, rng)?;
        debug_assert!(ss.len() == self.cols);
        //println!("ss={:?}\n", ss);
        let indices: Vec<Vec<(usize, FE::PrimeField)>> = (0..self.cols)
            .map(|i| lpn_mtx_indices::<FE>(i, self.rows, self.d))
            .collect();
        //println!("indices_receiver={:?}", indices);
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
        //println!("ys={:?}", ys);
        for i in 0..self.rows {
            self.v[i] = ys[i];
        }
        let output: Vec<FE> = ys.into_iter().skip(self.rows).collect();
        debug_assert!(output.len() == self.cols - self.rows);
        Ok(output)
    }
}
