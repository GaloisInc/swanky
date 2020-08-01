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
use blake2::{Blake2b, Digest};
use ff::Field;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Malicious};
use std::{arch::x86_64::*, convert::TryInto, marker::PhantomData};

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

/// Implement CopeeSender for Sender
impl<OT: OtSender<Msg = Block> + Malicious> CopeeSender for Sender<OT> {
    type Msg = Block;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _ot: PhantomData::<OT>,
        })
    }
    fn send<C: AbstractChannel>(&mut self, channel: &mut C, u: Fp) -> Result<Fpr, Error> {
        //Step 1.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut samples: Vec<(Block, Block)> = Vec::new();
        for i in 1..Params::M * Params::POWR {
            samples.push(rng.gen::<(Block, Block)>());
        }
        // Step 2.
        let mut ot = OT::init(channel, &mut rng).unwrap();
        ot.send(channel, &samples, &mut rng)?;
        // Step 3. // TODO start from here
        let mut wv: Vec<(Fp, Fp)> = Vec::new();
        for i in 1..Params::M * Params::POWR {
            // let w0 = PRF::compute(samples[i-1], j);
            //let w1 = PRF::compute(samples[i-1], j);
            //wv.push((w0, w1));
        }

        Ok(rng.gen::<Fpr>())
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

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Fpr, Error> {
        Ok(rand::random::<Fpr>())
        //TODO: Complete this later
    }
}
