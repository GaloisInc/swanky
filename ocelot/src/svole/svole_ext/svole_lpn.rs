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
        copee::to_fpr,
        svole_ext::{Params, LpnParams, SpsVoleReceiver, SpsVoleSender, LpnsVoleSender, LpnsVoleReceiver},
        CopeeReceiver,
        CopeeSender,
        SVoleReceiver,
        SVoleSender,
    },
};
use digest::generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use rand::{Rng, SeedableRng};
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
use rand_core::RngCore;
/// A LpnsVole sender.
#[derive(Clone)]
pub struct Sender<FE: FF, SV: SVoleSender, SPS: SpsVoleSender> {
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _sps: PhantomData<SPS>,
    svole: SV,
    spsvole: SPS,
    u: Vec<FE::PrimeField>, 
    w: Vec<FE>
}
/// A LpnsVole receiver.
pub struct Receiver<FE: FF, SV: SVoleReceiver, SPS: SpsVoleReceiver> {
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _sps: PhantomData<SPS>,
    svole: SV,
    spsvole: SPS,
    v: Vec<FE>,
}

/// Code generator G that outputs matrix A for the given dimension `k` by `n`.
pub fn code_gen<FE:FF>(rows: usize, cols: usize) -> Vec<Vec<FE>> {
    let mut res = Vec::default();
    let seed = rand::random::<Block>();
    let mut rng = AesRng::from_seed(seed);
    for i in 0..rows{
        for j in 0..cols{
            res[i][j] = FE::random(&mut rng);
        }
    }
    res
}

/// Compute dot product of two vectors
pub fn dot_product<FE:FF>(x:Vec<FE>, y:Vec<FE>) -> FE{
    assert_eq!(x.len(), y.len());
    let mut sum = FE::zero();
    for i in 0..x.len(){
        x[i].mul_assign(y[i]);
        sum.add_assign(x[i]);
    }
    sum
}

impl <FE: FF, SV: SVoleSender<Msg = FE>, SPS: SpsVoleSender> LpnsVoleSender for Sender<FE, SV, SPS>{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(channel: &mut C,
        rng: &mut RNG,) -> Result<Self, Error>{
        let svole_sender = SV::init(channel).unwrap();
        let (u, w) = svole_sender.send(channel).unwrap();
        let sp_svole_sender = SPS::init(channel).unwrap();
        Ok(Self {
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _sps: PhantomData::<SPS>,
            svole: svole_sender,
            spsvole: sp_svole_sender,
            u: u, 
            w: w
        })

    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,,
    ) -> Result<(Vec<FE::PrimeField>, Vec<FE>), Error>{
        let (a, c) = self.spsvole.send(channel).unwrap();
        let mut e = Vec::default();
        let mut t = Vec::default();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        // Sample error vector `e` with hamming weight `t`
        for i in 0..LpnParams::T{
            for j in 0..LpnParams::M{
                let rand_ind = rng.gen_range(0, LpnParams::M);
                e[rand_ind + i] = FE::PrimeField::one();
            }
        }
        for i in 0..LpnParams::T{
            for j in 0..LpnParams::M{
                let rand_ind = rng.gen_range(0, LpnParams::M);
                t[rand_ind + i] = FE::PrimeField::one();
            }
        }


        // Matrix A
        let a: Vec<Vec<FE::PrimeField>> = Vec::default();
        for i in 0..LpnParams::K{
            for j in 0..LpnParams::N{
                a[i][j] = FE::PrimeField::random(&mut rng);
            }
        }
        




    }

}

