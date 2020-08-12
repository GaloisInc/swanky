// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Correlated Oblivious Product Evaluation with errors (COPEe)
//!
//! This module provides implementations of COPEe Traits.

#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{RandomReceiver as ROTReceiver, RandomSender as ROTSender},
    svole::{CopeeReceiver, CopeeSender, Params},
    utils::bit_composition,
};
use rand::SeedableRng;
use scuttlebutt::{field::Fp, AbstractChannel, Aes128, AesRng, Block, Malicious};
use std::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{AddAssign, MulAssign, SubAssign},
};

/// A COPEe Sender.
#[derive(Clone)]
pub struct Sender<ROT: ROTSender + Malicious> {
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
}

/// A COPEe Receiver.
#[derive(Clone)]
pub struct Receiver<ROT: ROTReceiver + Malicious> {
    _ot: PhantomData<ROT>,
    delta: Fp,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Compute <g, x>.
pub fn g_dotprod(x: Vec<Fp>) -> Fp {
    let g: Fp = Fp::try_from(Fp::GEN).unwrap();
    let mut res: Fp = Fp::zero();
    for i in 0..Params::R {
        let mut sum: Fp = Fp::zero();
        for j in 0..Params::M {
            let mut two: Fp = Fp::one();
            two.add_assign(&Fp::one());
            let mut two_to_j: Fp = two.pow(Fp::try_from(j as u128).unwrap());
            two_to_j.add_assign(&x[(i * Params::M) + j]);
            sum.add_assign(&two_to_j);
        }
        let g_to_i: Fp = g.pow(Fp::try_from(i as u128).unwrap());
        sum.mul_assign(&g_to_i);
        res.add_assign(&sum);
    }
    res
}


/// Implement CopeeSender for Sender type
impl<ROT: ROTSender<Msg = Block> + Malicious> CopeeSender for Sender<ROT> {
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        /// Combine step 1 and 2 and by calling ROT.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let samples = ot
            .send_random(channel, Params::M * Params::R, &mut rng)
            .unwrap();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            sv: samples,
        })
    }
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<Fp>,
    ) -> Result<Vec<Fp>, Error> {
        let mut w: Vec<Fp> = Vec::new();
        for j in 0..input.len() {
            /// Step 3.
            let mut wv: Vec<(Fp, Fp)> = Vec::new();
            for i in 0..Params::M * Params::R {
                /// Aes encryption as a PRF
                let pt = Block::from(j as u128);
                let key0 = Block::from(self.sv[i].0);
                let cipher0 = Aes128::new(key0);
                let mut w0 = Fp::try_from(u128::from(cipher0.encrypt(pt))).unwrap();
                let key1 = Block::from(self.sv[i].1);
                let cipher1 = Aes128::new(key1);
                let w1 = Fp::try_from(u128::from(cipher1.encrypt(pt))).unwrap();
                wv.push((w0, w1));
                (w0.sub_assign(&w1));
                w0.sub_assign(&input[j]);
                channel.write_block(&Block::from(u128::from(w0)))?;
            }
            w.push(g_dotprod(wv.into_iter().map(|x| x.0).collect()));
        }
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<ROT: ROTReceiver<Msg = Block> + Malicious> CopeeReceiver for Receiver<ROT> {
    type Msg = Fp;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let delta: Fp = Fp::random(&mut rng);
        let deltab: Vec<bool> = bit_composition(delta);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            delta,
            choices: deltab,
            mv: ots,
        })
    }
    fn get_delta(&self) -> Fp {
        self.delta
    }
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<Fp>, Error> {
        let mut output: Vec<Fp> = Vec::new();
        for j in 0..len {
            let mut v: Vec<Fp> = Vec::new();
            for i in 0..Params::M * Params::R {
                let pt = Block::from(j as u128);
                let key = Block::from(self.mv[i]);
                let cipher = Aes128::new(key);
                let mut w_delta = Fp::try_from(cipher.encrypt(pt)).unwrap();
                let mut tau = Fp::try_from(channel.read_block().unwrap()).unwrap();
                tau.mul_assign(self.delta);
                w_delta.add_assign(&tau);
                v.push(w_delta);
            }
            output.push(g_dotprod(v));
        }
        Ok(output)
    }
}
