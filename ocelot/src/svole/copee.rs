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
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{CopeeReceiver, CopeeSender, Fp, Fpr, Params, Prf},
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
pub struct Sender<OT: OtSender + Malicious> {
    _ot: PhantomData<OT>,
}

/// A COPEe Receiver.
#[derive(Debug)]
struct Receiver<OT: OtReceiver + Malicious> {
    _ot: PhantomData<OT>,
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
impl<OT: OtSender<Msg = Block> + Malicious> CopeeSender for Sender<OT> {
    type Msg = Block;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _ot: PhantomData::<OT>,
        })
    }
    /// The input can be a vector: the following procedure can be executed as many times as the vector length.
    fn send<C: AbstractChannel, PRF: Prf>(
        &mut self,
        channel: &mut C,
        prf: &mut PRF,
        input: Fp,
    ) -> Result<Fpr, Error> {
        //Step 1.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut samples: Vec<(Block, Block)> = Vec::new();
        for _i in 1..Params::M * Params::POWR {
            samples.push(rng.gen::<(Block, Block)>());
        }
        // Step 2.
        let mut ot = OT::init(channel, &mut rng).unwrap();
        ot.send(channel, &samples, &mut rng)?;
        // Step 3.
        let mut wv: Vec<(Fp, Fp)> = Vec::new();
        for i in 1..Params::M * Params::POWR {
            let jb = Block::from(1 as u128);
            let mut w0 = prf.compute(samples[i - 1].0, jb);
            let w1 = prf.compute(samples[i - 1].1, jb);
            wv.push((w0, w1));
            (w0.sub_assign(&w1));
            w0.sub_assign(&input);
            channel.write_fp(w0)?;
        }

        Ok(g_dotprod(wv.into_iter().map(|x| x.0).collect()))
    }
}

/// Implement CopeeReceiver for Receiver
impl<OT: OtReceiver<Msg = Block> + Malicious> CopeeReceiver for Receiver<OT> {
    type Msg = Block;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _ot: PhantomData::<OT>,
        })
    }

    fn receive<C: AbstractChannel, PRF: Prf>(
        &mut self,
        channel: &mut C,
        prf: &mut PRF,
    ) -> Result<Fpr, Error> {
        //let u: Vec<Fp> = (1..Params::POWR*Params::M+1).map(|_| channel.read_fp().unwrap()).collect();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = OT::init(channel, &mut rng).unwrap();
        let deltab: Vec<bool> = (0..Params::POWR * Params::M)
            .map(|_| rng.gen::<bool>())
            .collect();
        let ots = ot.receive(channel, &deltab, &mut rng).unwrap();
        assert_eq!(ots.len(), Params::M * Params::POWR);
        let mut v: Vec<Fp> = Vec::new();
        for i in 1..Params::M * Params::POWR {
            let mut w_delta = prf.compute(ots[i - 1], Block::from(1 as u128));
            let mut tau = channel.read_fp()?;
            let dfp: Fp = PrimeField::from_str(&deltab[i - 1].to_string()).unwrap();
            tau.mul_assign(&dfp);
            w_delta.add_assign(&tau);
            v.push(w_delta);
        }
        assert_eq!(v.len(), Params::POWR * Params::M);
        Ok(g_dotprod(v))
    }
}
