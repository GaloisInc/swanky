// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector Oblivious Linear-function Evaluation (SVOLE)
//!
//! This module provides implementations of SVOLE Traits.



#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{CopeeReceiver, CopeeSender, Fp, Fpr, Prf, SVoleReceiver, SVoleSender, Params},
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
/// A SVOLE Sender.
#[derive(Debug)]
pub struct Sender<OT: OtSender + Malicious, CP: CopeeSender > {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>
}

/// A SVOLE Receiver.
#[derive(Debug)]
struct Receiver<OT: OtReceiver + Malicious, CP: CopeeReceiver >{
    _ot: PhantomData<OT>,
    _cp:PhantomData<CP>
}

impl<OT: OtSender<Msg = Block> + Malicious, CP: CopeeSender> SVoleSender for Sender<OT, CP> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C)-> Result<Self, Error>{
       let csender= CP::init(channel)?;
        Ok( Self{
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>
        })
    }

    fn send<C: AbstractChannel, PRF: Prf>(
        &mut self,
        channel: &mut C,
        prf: &mut PRF,
        input: Fp,
    ) -> Result<(Fpr, Fpr), Error>{
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut u: Vec<Fp> = Vec::new();
        for _i in 0..Params::N{
            u.push(rng.gen::<Fp>())
        }
        let mut a: Vec<Fp> = Vec::new();
        for _i in 0..Params::POWR{
            a.push(rng.gen::<Fp>());
        }
        let sender = CP::init(channel);
        for i in 0..u.len(){
            sender.send(channel, prf, u[i])?;
        }
        Ok(rand::random::<(Fpr, Fpr)>())
    }


}


impl<OT: OtReceiver<Msg = Block> + Malicious, CP: CopeeReceiver> SVoleReceiver for Receiver<OT, CP> {
    type Msg = Block;
    fn init<C: AbstractChannel>(channel: &mut C)-> Result<Self, Error>{
       let (cp_receiver, delta) = CP::init(channel).unwrap();
        Ok( Self{
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>
        })
    }


    fn receive<C: AbstractChannel, PRF: Prf>(
        &mut self,
        channel: &mut C,
        prf: &mut PRF,
    ) -> Result<Fpr, Error>{
        Ok(rand::random::<Fpr>())
    }


}
