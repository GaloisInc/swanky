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
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Malicious};
use std::marker::PhantomData;
//use num::pow;

/// A COPEe Sender.
#[derive(Debug)]
pub struct Sender<ROT: ROTSender + Malicious> {
    _ot: PhantomData<ROT>,
    sv: Vec<(Block, Block)>,
}

/// A COPEe Receiver.
#[derive(Debug)]
pub struct Receiver<ROT: ROTReceiver + Malicious> {
    _ot: PhantomData<ROT>,
    delta: Fp,
    choices: Vec<bool>,
    mv: Vec<Block>,
}

/// Compute <g, x>.

pub fn g_dotprod(x: Vec<Fp>) -> Fp {
    let g: Fp = PrimeField::multiplicative_generator();
    let mut res: Fp = Field::zero();
    for i in 0..Params::R {
        let mut sum: Fp = Field::zero();
        for j in 0..Params::M {
            let mut two: Fp = Field::one();
            two.add_assign(&Field::one());
            let mut two_to_j: Fp = two.pow([j as u64]);
            two_to_j.add_assign(&x[i * Params::M + j]);
            sum.add_assign(&two_to_j);
        }
        let g_to_i: Fp = g.pow([i as u64]);
        sum.mul_assign(&g_to_i);
        res.add_assign(&sum);
    }
    res
}

/// Implement CopeeSender for Sender
impl<ROT: ROTSender<Msg = Block> + Malicious> CopeeSender for Sender<ROT> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Vec<(Block, Block)>), Error> {
        //Step 1.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        /*let mut samples: Vec<(Block, Block)> = Vec::new();
        for _i in 1..Params::M * Params::R {
            samples.push(rng.gen::<(Block, Block)>());
        }*/
        // Step 2.
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        let samples = ot
            .send_random(channel, Params::M * Params::R, &mut rng)
            .unwrap();
        //assert_eq!(samples.len(), 128);
        let _samples = samples.clone();
        Ok((
            Self {
                _ot: PhantomData::<ROT>,
                sv: samples,
            },
            _samples,
        ))
    }
    /// The following procedure represent the sender computations of the extend procedure of the protocol.
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: Vec<Fp>,
    ) -> Result<Vec<Fpr>, Error> {
        let mut v: Vec<Fpr> = Vec::new();
        assert_eq!(Params::N, input.len());
        for _j in 0..input.len() {
            /// Step 3.
            let mut wv: Vec<(Fp, Fp)> = Vec::new();
            for i in 1..Params::M * Params::R {
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
            v.push(g_dotprod(wv.into_iter().map(|x| x.0).collect()));
        }
        Ok(v)
    }
}

/// Implement CopeeReceiver for Receiver
impl<ROT: ROTReceiver<Msg = Block> + Malicious> CopeeReceiver for Receiver<ROT> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<(Self, Fpr, Vec<Block>), Error> {
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut ot = ROT::init(channel, &mut rng).unwrap();
        //TODO: Fix this later
        let delta: Fp = rng.gen::<Fp>();
        let mut deltab: Vec<bool> = Vec::new();
        let temp_vec = ((delta.0).0).to_vec();
        for item in temp_vec.iter().take(2) {
            //for e in format!("{:b}", (delta.0).0)[i].chars(){
            for e in format!("{:b}", item).chars() {
                if e == '1' {
                    deltab.push(true);
                } else {
                    deltab.push(false);
                }
            }
        }
        if deltab.len() > Params::M {
            for _i in Params::M..deltab.len() + 1 {
                deltab.pop();
            }
        }
        /*
        //let fv: u128 = Binary::fmt(((delta.0).0)[0] as u128 +((delta.0).0)[1] as u128).unwrap();
        let deltab: Vec<bool> = (0..Params::M * Params::R)
            .map(|_| rng.gen::<bool>())
            .collect();
        let _db = deltab.clone();
        let temp: u128= (0..(deltab.len())).fold(0, |sum, i| sum + (pow(2, i as usize) * (u128::from(_db[i]))));
        //let s: String = _db.into_iter().map(|b| (b as u8) as char).collect();
        let delta: Fp = PrimeField::from_str(&temp.to_string()).unwrap();
        //let delta: Fp = Field::zero();
        /* let mut deltab: Vec<bool> = Vec::with_capacity(128);
        let fv1: u128 = ((delta.0).0)[0] as u128 +((delta.0).0)[1] as u128;
        for e in format!("{:b}", fv1).chars(){
            if e == '1' {
                deltab.push(true);
            }
            else{
                deltab.push(false);
            }
        }*/
        //assert_eq!(_db.len(), 128);
        // TODO: Optimize this later
        //let temp: u128= (0..(deltab.len())).fold(0, |sum, i| sum + (pow(2, (i as 64)) * (u128::from(deltab[i]))));
        //let t: u64 = 0;
        //let x: FpRepr = delta.into_repr();
        //let y = x.write_le(writer);
        //let delta: Fp = PrimeField::from_repr(<Fp as PrimeField>::Repr::from(t)).unwrap();*/
        assert_eq!(deltab.len(), Params::M * Params::R);
        let ots = ot.receive_random(channel, &deltab, &mut rng).unwrap();
        let _ots = ots.clone();
        Ok((
            Self {
                _ot: PhantomData::<ROT>,
                delta,
                choices: deltab,
                mv: ots,
            },
            delta,
            _ots,
        ))
    }

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        len: usize,
    ) -> Result<Vec<Fpr>, Error> {
        //let u: Vec<Fp> = (1..Params::R*Params::M+1).map(|_| channel.read_fp().unwrap()).collect();
        let mut output: Vec<Fp> = Vec::new();
        for _j in 0..len {
            assert_eq!(self.mv.len(), Params::M * Params::R);
            let mut v: Vec<Fp> = Vec::new();
            for i in 1..Params::M * Params::R {
                //let mut w_delta = prf.compute(self.mv[i - 1], Block::from(j as u128));
                let mut rng = AesRng::from_seed(self.mv[i - 1]);
                let mut w_delta = rng.gen::<Fp>();
                let mut tau = channel.read_fp()?;
                let dfp: Fp = PrimeField::from_str(&self.choices[i - 1].to_string()).unwrap();
                tau.mul_assign(&dfp);
                w_delta.add_assign(&tau);
                v.push(w_delta);
            }
            //assert_eq!(v.len(), Params::R * Params::M);
            output.push(g_dotprod(v));
        }
        Ok(output)
    }
}
