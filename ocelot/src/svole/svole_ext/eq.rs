// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang SpsVole protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use crate::{
    errors::Error,
    svole::svole_ext::{EqSender, EqReceiver}
};
use rand_core::{CryptoRng, RngCore};
use rand::Rng;
use scuttlebutt::{
    field::FiniteField,
    AbstractChannel,
    commitment::{Commitment, ShaCommitment}
};
use std::marker::PhantomData;

/// Eq Sender.
#[derive(Clone)]
pub struct Sender<FE: FiniteField>{
    _fe: PhantomData<FE>
}

impl <FE: FiniteField> EqSender for Sender<FE>{
    type Msg = FE;
    fn init() -> Result<Self, Error>{
        Ok(Self {_fe: PhantomData::<FE>})
    }
    fn send<C: AbstractChannel>(&mut self,
        channel: &mut C,
        input: &FE,
    ) -> Result<bool, Error>{
        let mut comm_vb = [0u8; 32];
        channel.read_bytes(&mut comm_vb)?;
        let va = *input;
        channel.write_fe(va)?;
        let mut seed = [0u8; 32];
        channel.read_bytes(&mut seed)?;
        let vb_: Result<FE, _> = channel.read_fe();
        match vb_ {
            Ok(fe) => {
                let mut commit = ShaCommitment::new(seed);
                commit.input(&fe.to_bytes());
                let res = commit.finish();
                if res == comm_vb {
                Ok(va == fe)
                }
                else{
                    Err(Error::Other("Failed Opening commitments".to_string()))
                }
            }
            Err(e) => Err(Error::Other(e.to_string()))
        }

    }    
} 

/// Eq Receiver.
#[derive(Clone)]
pub struct Receiver<FE: FiniteField> {
    _fe: PhantomData<FE>
}

impl <FE: FiniteField> EqReceiver for Receiver<FE>{
    type Msg = FE;
    fn init() -> Result<Self, Error>{
        Ok(Self {
            _fe: PhantomData::<FE>
        })
    }
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(&mut self,
        channel: &mut C,
        rng: &mut RNG,
        input:&FE,
    ) -> Result<bool, Error>{
        let vb = *input;
        let seed = rng.gen::<[u8;32]>();
        let mut commit = ShaCommitment::new(seed);
        commit.input(&vb.to_bytes());
        let result = commit.finish();
        channel.write_bytes(&result)?;
        let va: Result<FE, _> = channel.read_fe();
        match va {
            Ok(fe) => {
                channel.write_bytes(&seed)?;
                channel.write_fe(vb)?;
                Ok(fe == vb)
            }
            Err(e) => Err(Error::Other(e.to_string()))
        }
    }    
}