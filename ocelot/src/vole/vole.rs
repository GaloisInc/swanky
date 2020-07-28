// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of reverse VOLE functionality presented in
//! (<https://eprint.iacr.org/2019/1159>, Fig.14 page 25)

#![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{
    errors::Error,
    vole::{Fp, SenderDom, ReceiverDom},
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Malicious};
use crate::pprf::pprf::{read_fp, write_fp};
use std::arch::x86_64::*;
use ff::*;
use crate::pprf::{Tpprfreceiver, Tpprfsender, Fpstar};

/// Reverse VOLE parameters
pub struct Params;

/// Initialize parameters
impl Params {
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2 ^ Params::ELL;
    pub const T: usize = 10;
}

/// A VOLE Sender.

pub struct Sender<TPPRF: Tpprfreceiver>{
    _sv: PhantomData<TPPRF>,
}

/// A VOLE Receiver.
pub struct Receiver<TPPRF: Tpprfsender>{
    _rv: PhantomData<TPPRF>,
}

impl <TPPRF: Tpprfreceiver> VoleSender for Sender<TPPRF>{
    fn init()->Result<Self, Error>{
        Ok(Self{_sv: PhantomData::<TPPRF>})
    }
    fn send<C: AbstractChannel>(
        channel: &mut C
    ) -> Result<(), Error>{
        //TODO: Fix this later
        let LAMBDA = rand::random::<Block>();
        let mut rng = AesRng::from_seed(LAMBDA);
        let x = rng.gen::<Fp>();
        let kpprf = rng.gen::<Block>();
        let receiver = TPPRF::init();
        receiver.recerive(channel, kpprf, x);
        
    }
}

impl <TPPRF: Tpprfsender> VoleReceiver for Receiver<TPPRF>{
    fn init()->Result<Self, Error>{
        Ok(Self{_pv: PhantomData::<TPPRF>})
    }
    fn receive<C: AbstractChannel>(
        channel: &mut C
    ) -> Result<(), Error>{
        let LAMBDA = rand::random::<Block>();
        let mut rng = AesRng::from_seed(LAMBDA);
        let ev = (0..Params::N).map(|i| rng.gen::<Fpstar>());
        let alphas = (0..Params::T).map(|_| rng.gen::<Block>());

    }
}