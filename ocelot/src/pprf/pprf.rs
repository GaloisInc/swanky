// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.13 page 25)
//#[allow(unused_imports)]
//#[path = "../errors.rs"]
//mod errors;
//use crate ::errors::Error;
use crate:: pprf::{
    BitVec, Fpr2, PPRF, PprfSender, PprfReceiver, errors::Error};

//use ocelot;
//pub use bit_vec::BitVec;
//use galois_2p8;
//use rand::*;
use rand::distributions::{Distribution, Uniform};
#[allow(unused_imports)]
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
//use rand_core::block::{BlockRng, BlockRngCore};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, SemiHonest, AesRng};
//#[allow(unused_imports)]
//pub use crate::{pprf::{PprfSender, BitVec, Fpr, Fpr2}};
extern crate byteorder;
use blake2::{Blake2b, Blake2s, Digest};
use hex_literal::hex;
use std::convert::TryInto;
use generic_array::{ArrayLength, GenericArray};
use std::arch::x86_64::*;

/// Parameters for the mal-PPRF protocol
pub struct Params;
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2^Params::ELL;
}

/// Sender
#[derive(Clone, Debug)]
pub struct Sender {
    beta: Fpr2,
    kpprf: Block,
    c: Fpr2,
    k1: Block,
    // Change this to Block512 later
    hash: Block512,
}

/// Receiver
#[derive(Clone, Debug)]
struct Receiver {
    alpha: Block,
    kstar: Block,
    w: Fpr2,
}
#[allow(dead_code)]
type PprfRange = (Fpr2, Block);

/// legnth-doubling PRG G
#[allow(dead_code)]
fn prg_g(seed: Block) -> (Block, Block) {
    /// generates new random generator from seed.
    let mut rng = AesRng::from_seed(seed);
    let s1 = rng.gen::<Block>();
    let s2 = rng.gen::<Block>();
    (s1, s2)
}
/// PRG G': used to compute the PRF outputs on the last level of the tree
#[allow(dead_code)]
fn prg_gprime(seed: Block) -> PprfRange {
    //TODO complete the definition
    /*let mut bv = BitVec::from_bytes(&[0b00000000]);
    #[allow(deprecated)]
    bv.union(&x);
    let z = (0, 0);
    (z, bv)*/
    let (s0, s1) = rand::random::<(Block, Block)>();
    let s = rand::random::<Block>();
    ((s0, s1), s)
}



/// implement PprfSender for Sender

impl PprfSender for Sender {
    type Msg = Block;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        // Sampling the key kpprf
        let seed = rand::random::<Block>();
        // chose input beta uniformly
        let beta = rand::random::<Fpr2>();
        /// To store the intermediate evaluations of the GGM tree
        let mut v: Vec<Block> = vec![seed];
        /// To store the evaluations on the last level of the tree
        let mut b: Vec<PprfRange> = Vec::new();
        //TODO: optimize it later
       /* let kspace = Uniform::from(0..2 ^ (Params::LAMBDA) - 1);
        let res = kspace.sample(&mut rng) as f32;
        let ns = res.log(2.0) as usize;
        let s0 = BitVec::with_capacity(ns);*/
        /// 2.b compute (s^i_{2j}, s^i_{2j+1}) = G(s^{i-1}_j)
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
                let s = v[i - 1 + j].clone();
                let (s0, s1) = prg_g(s);
                v.push(s0);
                v.push(s1);
            }
        }
        /// 2.c compute (s^{l+1}_{2j}, s^{l+1}_{2j+1})
        for j in 0..2 ^ (Params::ELL + 1) {
            let temp = v[Params::ELL + j].clone();
            let pair = prg_gprime(temp);
            b.push(pair);
        }
        /// compute the left and right halves of intermediate levels
        let mut k0: Vec<Block> = Vec::new();
        let mut k1: Vec<Block> = Vec::new();
        let mut temp1 =  Block(unsafe {_mm_setzero_si128()});
        let mut temp2 =  Block(unsafe {_mm_setzero_si128()});
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
               let temp1 = temp1^v[i + j];
               let temp2 = temp2^v[i + j + 1];
            }
            k0.push(temp1);
            k1.push(temp2);
        }
        ///4. compute right half for the last level l+1.
        let mut temp = Block(unsafe {_mm_setzero_si128()});
        for j in b.iter() {
            let temp=temp^j.1;
        }
        ///5. Parallel OT calls
        for i in 1..Params::ELL + 1 {}
        ///6. compute correction value
        let (left, _): (Vec<Fpr2>, Vec<_>) = b.iter().cloned().unzip();
        let (left1, right1): (Vec<_>, Vec<_>) = left.iter().cloned().unzip();
        //TODO: fix the following
        //let l: Block = (self.beta.0).0-left1.iter().sum();
        //let r: Block = self.beta.1-right1.iter().sum();
         let l: Block = Block ((self.beta.0).0);
        let r: Block = Block ((self.beta.1).0);
        let c = (l, r);
        /// 7. apply hash function.
        let mut hasher = Blake2b::new();
        let (l, r): (Vec<_>, Vec<_>) = b.iter().cloned().unzip();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(r[i]);
        }
        let hash = hasher.finalize();
        let gamma = hash.as_slice().try_into().unwrap();

        Ok(Self{kpprf:seed, beta:beta, c:c, k1:temp, hash:gamma})
    }
   

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        for (k, c, gamma) in inputs.iter() {
            channel.write_block(&k)?;
            channel.write_block(&c)?;
            channel.write_block(&gamma)?;
        }
        channel.flush()?;
        Ok(())
    }
}



impl PprfReceiver for Receiver{
    type Msg = Block;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>{
        // TODO: implement this later
        Err(Error::InvalidInputLength)
    }
    fn puncture(keys: Vec<BitVec>, alpha: bool)-> BitVec{
        let kstar = BitVec::new();
        kstar
    }

    fn fulleval(pkey: BitVec, alpha: bool)-> Vec<BitVec>{
        let mut bv = BitVec::from_elem(0, alpha);
        bv.set(1, false);
        let ppoint = bv.to_bytes()[0] as u32;
        let mut res:Vec<BitVec> = Vec::new();
        for j in 1..Params::N+1 {
            if j == ppoint.try_into().unwrap() {
                break;
            }
            // TODO: fix this to correct computation later
            let temp = BitVec::from_bytes(&j.to_be_bytes());
            res.push(temp);
        }
    res
    }
    
    fn verify(gamma: &[u8], alpha:u32) -> Option<u32>{
        // compute w 
        let c:u32 = 1000;
        let mut s:Vec<u32> = Vec::new();
        s.remove(alpha as usize);
        let sum:u32 = s.iter().sum();
        let w = c - sum;
        // apply hash function
        let mut hasher = Blake2b::new();
        let vec_gamma:Vec<BitVec> = Vec::new();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(vec_gamma[i].to_bytes());
        }
        let hash= hasher.finalize();
        let gamma_prime:&[u8] = hash.as_slice();
        if gamma == gamma_prime
        {
            Some(w)
        }
        else {None}
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        //TODO: complete this definition
       inputs.iter().map(|_x| {
           let c = channel.read_block()?;
           Ok(c)
        }).collect()
    }
}

