// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.16 page 26)

#![allow(unused_imports)]
#![allow(dead_code)]
use crate::{
    errors::Error,
    ot::{Sender as OtSender, Receiver as OtReceiver, ChouOrlandiSender, ChouOrlandiReceiver, chou_orlandi},
    pprf::{BitVec, PprfSender, PprfReceiver, Fp, Fp2}
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, AesRng, Channel};
use crate::pprf::{Tpprfsender, Tpprfreceiver};
/// tpprf parameters
pub struct Params;
/// intialize the parameters
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2^Params::ELL;
    pub const T: usize = 10;
    }
/// tpprf sender
pub struct Sender{
    x: Fpr,
    beta: Vec<Fpr>,
    b: Vec<Fpr>,
    chi: Fpr,
}

use crate::vole::*;

impl Tpprfsender for Sender {
    // add code here
    fn init()-> Result<Self, Error>{
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let beta: Vec<Fpr> = (0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let b: Vec<Fpr> = (0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let chi: Fpr = rng.gen::<Fpr>();
        let x:Fpr = rng.gen::<Fpr>();
        Ok(Self{x, beta, b, chi})
    }

    fn send() -> Result<(), Error>{
        Ok(())
    }
}

type Fprstar = Block;
/// tpprf Receiver 
pub struct Receiver{
    s: Vec<Block>,
    y: Vec<Fprstar>
}


impl Tpprfreceiver for Receiver {
    // add code here
    fn init()-> Result<(), Error>{
        Ok(())
    }
}
