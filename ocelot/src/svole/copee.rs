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
    svole::{CopeeReceiver, CopeeSender, Fp, Fpr, Params},
};
use ff::*;
use num::pow;
//#[cfg(feature = "derive")]
//pub use ff_derive::*;
use ff::PrimeField;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Malicious};
use std::marker::PhantomData;
//use scuttlebutt::ff_derive::Fp as PrimeField;
/// A COPEe Sender.
#[derive(Debug)]
pub struct Sender<ROT: ROTSender + Malicious> {
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
}

/// A COPEe Receiver.
#[derive(Debug)]
struct Receiver<ROT: ROTReceiver + Malicious> {
    _ot: PhantomData<ROT>,
    delta: Fp,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

pub fn g_dotprod(x: Vec<Fp>) -> Fp {
    let mut res: Fp = Field::zero();
    for i in 0..Params::POWR {
        let mut sum: Fp = Field::zero();
        for j in 0..Params::M {
            let mut temp: Fp = PrimeField::from_str(&pow(2, j).to_string()).unwrap();
            temp.add_assign(&x[i * Params::M + j]);
            sum.add_assign(&temp);
        }
        sum.mul_assign(&PrimeField::from_str(&pow(7, i).to_string()).unwrap());
        res.add_assign(&sum);
    }
    res
}

/// Implement CopeeSender for Sender
impl<ROT: ROTSender<Msg = Block> + Malicious> CopeeSender for Sender<ROT> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        //Step 1.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        /*let mut samples: Vec<(Block, Block)> = Vec::new();
        for _i in 1..Params::M * Params::POWR {
            samples.push(rng.gen::<(Block, Block)>());
        }*/
        // Step 2.
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let samples = ot
            .send_random(channel, Params::M * Params::POWR, &mut rng)
            .unwrap();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            sv: samples,
        })
    }
    /// The input can be a vector: the following procedure can be executed as many times as the vector length.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<Fp>,
    ) -> Result<Vec<Fpr>, Error> {
        let mut output: Vec<Fpr> = Vec::new();
        assert_eq!(Params::IPLENGTH, input.len());
        for _j in 0..input.len() {
            // Step 3.
            let mut wv: Vec<(Fp, Fp)> = Vec::new();
            for i in 1..Params::M * Params::POWR {
                //let jb = Block::from(j as u128);
                //TODO: Figure out PRF that depends on k and jb
                //let mut w0 = prf.compute(self.sv[i - 1].0, jb);
                let mut rng1 = AesRng::from_seed(self.sv[i - 1].0);
                let mut w0 = rng1.gen::<Fp>();
                let mut rng2 = AesRng::from_seed(self.sv[i - 1].1);
                let w1 = rng2.gen::<Fp>();
                //let w1 = prf.compute(self.sv[i - 1].1, jb);
                wv.push((w0, w1));
                (w0.sub_assign(&w1));
                w0.sub_assign(&input[i - 1]);
                channel.write_fp(w0)?;
            }
            output.push(g_dotprod(wv.into_iter().map(|x| x.0).collect()));
        }
        Ok(output)
    }
}

/// Implement CopeeReceiver for Receiver
impl<ROT: ROTReceiver<Msg = Block> + Malicious> CopeeReceiver for Receiver<ROT> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Fpr), Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let delta: Fp = rng.gen::<Fp>();
        let deltab = unsafe { std::mem::transmute::<Fp, Vec<bool>>(delta) };
        assert_eq!(deltab.len(), Params::M * Params::POWR);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        Ok((
            Self {
                _ot: PhantomData::<ROT>,
                delta,
                choices: deltab,
                mv: ots,
            },
            delta,
        ))
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Vec<Fpr>, Error> {
        //let u: Vec<Fp> = (1..Params::POWR*Params::M+1).map(|_| channel.read_fp().unwrap()).collect();
        let mut output: Vec<Fp> = Vec::new();
        for _j in 0..Params::IPLENGTH {
            assert_eq!(self.mv.len(), Params::M * Params::POWR);
            let mut v: Vec<Fp> = Vec::new();
            for i in 1..Params::M * Params::POWR {
                //let mut w_delta = prf.compute(self.mv[i - 1], Block::from(j as u128));
                let mut rng = AesRng::from_seed(self.mv[i - 1]);
                let mut w_delta = rng.gen::<Fp>();
                let mut tau = channel.read_fp()?;
                let dfp: Fp = PrimeField::from_str(&self.choices[i - 1].to_string()).unwrap();
                tau.mul_assign(&dfp);
                w_delta.add_assign(&tau);
                v.push(w_delta);
            }
            assert_eq!(v.len(), Params::POWR * Params::M);
            output.push(g_dotprod(v));
        }
        Ok(output)
    }
}
