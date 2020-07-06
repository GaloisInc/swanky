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
extern crate byteorder;


/// Parameters for the mal-PPRF protocol
pub struct Params; 
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
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
fn prg_g (x:BitVec) -> (BitVec, BitVec) {
    //TODO optimize the code later
    assert_eq!(x.len(), Params::LAMBDA);
    let mut rng = rand::thread_rng();
    let ks = Uniform::from(0..2^(Params::LAMBDA));
    let sample1 = ks.sample(&mut rng).to_le_bytes();
    let bv1 = BitVec::from_bytes(&sample1);
    let sample2 = ks.sample(&mut rng).to_le_bytes();
    let bv2 = BitVec::from_bytes(&sample2);
    assert_eq!(bv1.len(), Params::LAMBDA);
    assert_eq!(bv2.len(), Params::LAMBDA);
    (bv1, bv2)
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

/// GGM Puncturable PRF constructed using prg_g
#[allow(dead_code)]
fn pprf_ggm (_x: BitVec, k:BitVec) -> PprfRange { 
    //TODO complete the definition
    let bv = BitVec::from_elem(k.len(), false);
    let x = (0,0);
    (x, bv)
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
    
    fn compute(x: BitVec)-> (BitVec, Fpr2){
        //TODO fix this definition later
        assert_eq!(x.len(), Params::LAMBDA);
        let mut v:Vec<BitVec> = vec![x];
        let mut b:Vec<PprfRange> = Vec::new();
        for i in 1..Params::ELL+1{
            for j in 0..2^(i-1){
                let temp = v[i-1+j].clone();
                let (s0, s1) = prg_g(temp);
                v.push(s0);
                v.push(s1);
            }
            
            for j in 0..2^(Params::ELL+1){
                let temp = v[Params::ELL+j].clone();
                let pair = prg_gprime(temp);
                b.push(pair);
            }

        }
        // compute the left and right halves
        let mut k0:Vec<BitVec> = Vec::new();
        let mut k1:Vec<BitVec> = Vec::new();
        for i in 1..Params::ELL+1 {
            let mut temp1 = BitVec::new();
            let mut temp2 = BitVec::new();
            for j in 0..2^(i-1){
                temp1.xor(&v[i+j].clone());
                temp2.xor(&v[i+j+1].clone());
            }
            k0.push(temp1);
            k1.push(temp2);
        }
         // compute right half for i = ELL+1
         let mut temp = BitVec::new();
         for j in b.iter(){
             temp.xor(&j.1);
         }
            k1.push(temp);
         //step5: Parallel OT calls
         for i in 1..Params::ELL+1{

         }
         // compute correlation value
         let s1 = Sender{beta:(10,10), kpprf:BitVec::new()};
         // use unzip
         let (left, _):(Vec<Fpr2>, Vec<_>) = b.iter().cloned().unzip();
         let (left1, _):(Vec<_>, Vec<_>) = left.iter().cloned().unzip(); 
         let sum:u32= left1.iter().sum();
         let c:u32 = s1.beta.0-sum;
        let x = BitVec::new();
        (k1.pop(), (c, c));
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
     



/// A trait for PPRF Receiver
pub trait PprfReceiver{    
   
}
