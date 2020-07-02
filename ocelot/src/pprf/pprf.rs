// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol 
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.13 page 25)
//#[allow(unused_imports)]
#[path = "../errors.rs"]
mod errors;
//use crate ::errors::Error;
use crate::{
    pprf::{BitVec, Fpr2},
};

//use ocelot;
//pub use bit_vec::BitVec;
//use galois_2p8;
//use rand::*;
#[allow(unused_imports)]
use rand::{CryptoRng, Rng, thread_rng};
use rand::distributions::{Distribution, Uniform};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};
//#[allow(unused_imports)]
//pub use crate::{pprf::{PprfSender, BitVec, Fpr, Fpr2}};



/// Parameters for the mal-PPRF protocol
pub struct Params {
    pub lambda : u32,
    pub l : u32,
    pub p : u32,
    pub r : u32 
}


 
/// Sender
#[derive(Clone, Debug)]
struct Sender {
    beta: Fpr2,
    kpprf: BitVec
}

/// Receiver 
#[derive(Clone, Debug)]
struct Receiver {
    alpha: BitVec
}
#[allow(dead_code)]
type PprfRange = (Fpr2, BitVec);

/// legnth-doubling PRG G
#[allow(dead_code)]
fn prg_g (x:BitVec) -> BitVec {
    //TODO complete the definition
    let bv = BitVec::with_capacity(2*(x.len()));
    bv
 }

/// GGM Puncturable PRF constructed using prg_g
#[allow(dead_code)]
fn pprf_ggm (_x: BitVec, k:BitVec) -> PprfRange { 
    //TODO complete the definition
    let bv = BitVec::from_elem(k.len(), false);
    let x = (0,0);
    (x, bv)
}

/// PRG G': used to compute the PRF outputs on the last level of the tree
#[allow(dead_code)]
fn prg_gprime (x:BitVec) -> PprfRange {
    //TODO complete the definition
    let mut bv = BitVec::from_bytes(&[0b00000000]);
    #[allow(deprecated)]
    bv.union(&x);
    let z = (0,0);
    (z, bv)
}


/// A trait for PPRF Sender
pub trait PprfSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// samples a random seed
    fn sample_rand_seed(x:u32) -> BitVec;
    /// compute a pair of messages
    fn compute (x:BitVec) -> (BitVec, Fpr2);

    // send a triple consists of key, c values, and the Gamma
     
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block, Block)],
        _: &mut RNG,
    ) -> Result<(), errors::Error> ;
}

/// A trait for PPRF Receiver
pub trait PprfReceiver{    
}

/// implement PprfSender for Sender

impl PprfSender for Sender {
    type Msg = Block;

    fn sample_rand_seed(_lamda:u32) -> BitVec<u32>{
        //TODO fix this definition later
        let mut rng = rand::thread_rng();
        const TEMP:u32 = 10; //lambda
        let kspace = Uniform::from(0..2^(TEMP)-1);
        let res = kspace.sample(&mut rng) as f32;
        let ns = res.log(2.0) as usize;
        let bv = BitVec::with_capacity(ns);
        let _s = res as u32;
        bv
    }
    
    fn compute(_x: BitVec)-> (BitVec, Fpr2){
        //TODO fix this definition later
        let x = BitVec::new();
        (x, (0, 0))
    }
    
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block, Block)],
        _: &mut RNG,
    ) -> Result<(), errors::Error> {
       
        for (k, c, gamma) in inputs.iter() {
            channel.write_block(&k)?;
            channel.write_block(&c)?;
            channel.write_block(&gamma)?;
        }
        channel.flush()?;
        Ok(())
    }
}
     



