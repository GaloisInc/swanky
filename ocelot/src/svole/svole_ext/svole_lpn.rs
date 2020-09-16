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
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        svole_ext::{LpnsVoleReceiver, LpnsVoleSender, SpsVoleReceiver, SpsVoleSender},
        CopeeReceiver,
        CopeeSender,
        SVoleReceiver,
        SVoleSender,
        svole_utils::{to_fpr, dot_prod}
    },
};
use generic_array::GenericArray;
use rand::{Rng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    AesRng,
    Block,
    Malicious,
};
use std::{
    marker::PhantomData,
    ops::{MulAssign, SubAssign},
};

/// A LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FF, SV: SVoleSender, SPS: SpsVoleSender> {
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _sps: PhantomData<SPS>,
    svole: SV,
    spsvole: SPS,
    rows: usize,
    u: Vec<FE::PrimeField>,
    w: Vec<FE>,
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
    v: Vec<FE>,
}

/// Code generator G that outputs matrix A for the given dimension `k` by `n`.
pub fn code_gen<FE: FF>(rows: usize, cols: usize) -> Vec<Vec<FE>> {
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
        k: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut svole_sender = SV::init(channel, rng).unwrap();
        let uw = svole_sender.send(channel, k, rng)?;
        let u = uw.iter().map(|&uw| uw.0).collect();
        let w = uw.iter().map(|&uw| uw.1).collect();
        let sp_svole_sender = SPS::init(channel, rng).unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _sps: PhantomData::<SPS>,
            svole: svole_sender,
            spsvole: sp_svole_sender,
            rows: k,
            u,
            w
        })
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<(Vec<FE::PrimeField>, Vec<FE>), Error> {
        let m = cols / weight;
        let ac = self.spsvole.send(channel, m as u128, rng).unwrap();
        let mut e = vec![FE::PrimeField::zero(); cols];
        let mut t = vec![FE::PrimeField::zero(); weight];
        // Sample error vector `e` with hamming weight `t`
        for i in 0..weight {
            let ind = rng.gen_range(0, weight);
            e[i*weight+ind] = FE::PrimeField::one();
    }
    for i in 0..weight {
        let ind = rng.gen_range(0, weight);
        t[i*weight+ind] = FE::PrimeField::one();
}
        let a = code_gen::<FE::PrimeField>(self.rows, cols);
        let a_prime: Vec<Vec<FE>> = a.iter().map(|&u| u.iter().map(|&u| to_fpr::<FE>(u).collect())).collect();
        let x: Vec<FE::PrimeField> = (0..self.rows).map(|i| dot_prod(&self.u, &a[i])).collect();
        x = x.iter().zip(e.iter()).map(|(&x_, &e_)| x_ + e_).collect();
        let z = (0..self.rows).map(|i| dot_prod::<FE>(&self.w, &a[i])).sum();
        z += t;
        let u = vec![FE::PrimeField::zero(); cols];
        let w = vec![FE::zero(); cols];
        Ok((u, w))
    }
}

impl<FE: FF, SV: SVoleReceiver<Msg = FE>, SPS: SpsVoleReceiver> LpnsVoleReceiver for Receiver<FE, SV, SPS> {
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        k: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut svole_receiver = SV::init(channel, rng).unwrap();
        let v = svole_receiver.receive(channel, k, rng)?;
        let sp_svole_receiver = SPS::init(channel, rng).unwrap();
        let delta = FE::random(&rng);
        Ok(Self {
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _sps: PhantomData::<SPS>,
            svole: svole_receiver,
            spsvole: sp_svole_receiver,
            delta,
            v,
        })
    }
        fn delta(&self) -> FE{
            self.delta
        }
    
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let m = cols / weight;
        let b = self.spsvole.receive(channel, m as u128, rng)?;
        let mut s = vec![FE::zero(); weight];
       // define the vectors e and t.
        for _i in 0..weight {
            let rand_ind = rng.gen_range(0, weight);
            s[rand_ind] = FE::one();
        }
        let y = (0..self.rows).map(|i| dot_product(&self.v, &a[i])).sum();
        y.add_assign(s);
       
        let v = vec![FE::zero(); cols];
        Ok(v)
    }
}

