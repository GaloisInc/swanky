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
    field::*,
    ot::{Sender as OtSender, Receiver as OtReceiver},
    pprf::{PprfSender, PprfReceiver, Fp, Fp2, Fpstar, PPRF as PPRFTrait}
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, AesRng, Channel};
use crate::pprf::{Tpprfsender, Tpprfreceiver, PPRF, pprf::{write_fp, read_fp}};
use crate::vole::{Rvolesender, Rvolereceiver};
use std::{marker::PhantomData};
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

pub struct Sender<RVOLE: Rvolesender, PS:PprfSender, PT:PPRFTrait >{
    _sv: PhantomData<RVOLE>,
    _sp: PhantomData<PS>,
    _spt: PhantomData<PT>
}
pub struct Receiver<RVOLE: Rvolereceiver, PR:PprfReceiver, PT:PPRFTrait>{
    _rv: PhantomData<RVOLE>,
    _rp: PhantomData<PR>,
    _rpt: PhantomData<PT>
}


use crate::vole::*;
use ff::*;

impl <RVOLE:Rvolesender, PS:PprfSender, PT:PPRFTrait> Tpprfsender for Sender<RVOLE, PS, PT> {
    fn init() -> Result<Self, Error>{
        Ok(Self{_sv: PhantomData::<RVOLE>,
        _sp: PhantomData::<PS>,
        _spt: PhantomData::<PT>})
    }
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x: Fp
    ) -> Result<(), Error>{
     //TODO: Fix the security parameter
     let lambda = rand::random::<Block>();
     let mut rng = AesRng::from_seed(lambda);
     let beta: Vec<Fp> = (0..Params::T).map(|_| rng.gen::<Fp>()).collect();
     let _beta = beta.clone();
     let b: Vec<Fp> = (0..Params::T).map(|_| rng.gen::<Fp>()).collect();
     let _b = b.clone();
     let chi = rng.gen::<Fp>();
     RVOLE::send(channel, ((beta, chi), (b, x))).unwrap();
     /// Sender need to call PPRF sender
     use crate::pprf::pprf::Sender;
     //let sv1 = Vec::new();
     //let sv2 = Vec::new();
     /// To store partial evaluation of the last level l+1.
     /// let temp:PPRF = PPRF::new();
     let mut sender= PS::init().unwrap();
     for i in 0..Params::T{
     sender.send( channel, (_beta[i], _b[i]), lambda).unwrap();
     }
     /// 5. computes (vjs,2i, vjs,2i+1)
     let tau_vec:Vec<Fp> = (0..Params::N+2).map(|_| read_fp(channel).unwrap()).collect();
     let mut _tau:Fp = tau_vec[0].clone();
     _tau.mul_assign(&x);
     _tau.add_assign(&chi);
     write_fp(channel, _tau)?;
     // TODO: fix this later
     //let mut vs: Vec<(Block, Block)> = Vec::new();
     let ks:Vec<Block> = (0..Params::T).map(|_| rng.gen::<Block>()).collect();
     let mut vs:Vec<(Fp, Fp)> = Vec::new();
     //let _ks = ks.clone();
     for j in 0..Params::T {
     for i in 0..Params::N {
            let s = ks[i].clone();
            // TODO: Fix this later pprfeval (kj, i)
            //let (s0, s1) = PPRF::prg_g::<CryptoRng>(s, &mut rng);
            //vs.push(s0);
            vs.push(rng.gen::<(Fp, Fp)>());
        }
    }
    let _vs: Vec<Fp> = Vec::new();
    for j in 0..Params::T{
        let mut _temp = tau_vec[0].clone();
        let v:Fp = (0..Params::N).into_iter().fold(Field::zero(), |mut sum, i| {
            _temp.mul_assign(&vs[j+i].1);
            _temp.add_assign(&vs[j+i].0);
            _temp.mul_assign(&tau_vec[i+1]);
            sum.add_assign(&_temp);
            sum
        });
        write_fp(channel, v)?;
    }
    Ok(())
}
}

/// tpprf Receiver 

impl <RVOLE:Rvolereceiver, PR:PprfReceiver, PT:PPRFTrait>Tpprfreceiver for Receiver<RVOLE, PR, PT> {
    fn init() -> Result<Self, Error>{
        Ok(Self{_rv: PhantomData::<RVOLE>,
        _rp: PhantomData::<PR>,
        _rpt: PhantomData::<PT>})
    }
    fn receive<C:AbstractChannel>(
        &mut self,
        channel: &mut C,
        s: Vec<Block>,
        y: Vec<Fpstar>
    ) -> Option <(Vec<Block>, Vec<Block>, Vec<Block>, Vec<Fpstar>)>{
        let lambda = rand::random::<Block>();
        let mut rng = AesRng::from_seed(lambda);
        let mut _y = y.clone();
        /// RVOLE call
        let (gamma, c) = RVOLE::receive(channel, y).unwrap();    
        /// PPRF calls 
        let mut receiver = PR::init().unwrap();
        let rblocks:Vec<Block> = (0..Params::T).map(|_| rng.gen::<Block>()).collect();
        let ots: Vec<Option<(Vec<Block>, (Fp, Fp))>>  = (0..Params::T).map(|i| receiver.receive(channel, rblocks[i])).collect();
        // Check if there is a None in the vector.
        if ots.iter().any(|x| *x== None) 
        {
          None 
        }
        else {
        /// 4. R samples taus
        let tau_vec:Vec<Fp> = (0..Params::N+1).map(|_| rng.gen::<Fp>()).collect();
        for i in 0..Params::N+1{
            write_fp(channel, tau_vec[i]).unwrap();
        } 
        /// R receives X = chi + tau.x
        let mut x = read_fp(channel).unwrap();
        let vs:Vec<Fp> = (0..Params::T).map(|_| read_fp(channel).unwrap()).collect();
        /// 6. R computes Eval'
        let mut rv: Vec<(Fp, Fp)> = Vec::new();
        let kjstar: Vec<Block> = (0..Params::T).map(|_| rng.gen::<Block>()).collect();
        let zj: Vec<Block> = (0..Params::T).map(|_| rng.gen::<Block>()).collect();
        for j in 0..Params::T {
            for i in 0..Params::N {
                   let s = s[i].clone();
                   // TODO: Fix this later pprfeval (kj, i)
                   let (s0, s1) = PT::prg_g(s, &mut rng);
                   //vs.push(s0);
                   rv.push(rng.gen::<(Fp, Fp)>());
               }
           }
        /// Read Vsj from sender
        let mut _rv: Vec<Fp> = Vec::new();
        for j in 0..Params::T{
            let mut _temp = tau_vec[0].clone();
            let v:Fp = (0..Params::N).into_iter().fold(Field::zero(), |mut sum, i| {
                _temp.mul_assign(&rv[j+i].1);
                _temp.add_assign(&rv[j+i].0);
                _temp.mul_assign(&tau_vec[i+1]);
                sum.add_assign(&_temp);
                sum
            });
            _rv.push(v);
        }

        /// Receiver checks
        let checks:Vec<bool> = (0..Params::T).map(|j| {
             x.mul_assign(&tau_vec[j].clone());
             x.mul_assign(&_y[j]);
            _rv[j] == x
        }).collect();
        if checks.iter().any(|&x| x == false){
            None
        }
        else {
            // TODO: FromIterator not implemented for Vec<Block>
            //let kz = kjstar.iter().zip(zj.iter()).into_iter().map(|x| x).collect();

            let k0: (Vec<Block>, Vec<Block>, Vec<Block>, Vec<Fpstar>) = (kjstar, zj,s, _y);
            Some(k0)
        }
        }

} }
