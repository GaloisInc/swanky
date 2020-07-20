// -*- mode: rust; -*-
//
// This file is part of ocelot.

// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.13 page 25)
//#[allow(unused_imports)]

extern crate rand;
use crate::{
    errors::Error,
    ot::{Sender as OtSender, Receiver as OtReceiver, ChouOrlandiSender, ChouOrlandiReceiver},
    pprf::{BitVec, PprfSender, PprfReceiver, Fp, Fp2}
};

#[allow(unused_imports)]
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
//use rand_core::block::{BlockRng, BlockRngCore};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, SemiHonest, AesRng, Channel};
#[allow(unused_imports)]
extern crate byteorder;
use blake2::{Blake2b, Blake2s, Digest};
use hex_literal::hex;
use std::convert::TryInto;
use generic_array::{ArrayLength, GenericArray};
use std::arch::x86_64::*;
//use crate::field::Fp;


/// Parameters for the mal-PPRF protocol
pub struct Params;
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2^Params::ELL;
}

#[allow(dead_code)]
type PprfRange = (Fp2, Block);


// Define static variable
lazy_static! {
static ref ZERO:__m128i = unsafe { _mm_setzero_si128() };
}



/// PPRF Sender
#[derive(Debug)]
pub struct Sender {
    // To store partial evaluations of the intermediate levels
    sv1: Vec<Block>,
    // To store partial evaluation of the last level l+1
    sv2: Vec<PprfRange>
}

impl Sender{
    pub fn new() -> Sender{
        Sender {
            sv1: Vec::new(),
            sv2: Vec::new()
        }
    }
}
   
/// PPRF Receiver
#[derive(Debug)]
struct Receiver {
   // A vector to store all the evaluations s_j suchthat j is not equal to alpha||0
   rv: Vec<Block>
}

/*impl Receiver{
    pub fn new() -> Receiver{
        Receiver {
            rv: Vec::new()
        }
    }
}*/

/// legnth-doubling PRG G
#[allow(dead_code)]
fn prg_g(seed: Block) -> (Block, Block) {
    // Generate RNG using seed.
    let mut rng = AesRng::from_seed(seed);
    let pair = rng.gen::<(Block, Block)>();
    pair
}

/// PRG G': used to compute the PRF outputs on the last level of the tree
#[allow(dead_code)]
fn prg_gprime(seed: Block) -> PprfRange {
    let mut rng = AesRng::from_seed(seed);
    let triple = rng.gen::<PprfRange>();
    triple
}



/// implement PprfSender for Sender

impl PprfSender for Sender {
    type Msg = Block;
    fn init(&mut self) -> Result<(), Error> {
        //! Sampling the key kpprf.
        let seed = rand::random::<Block>();
        // chose input beta uniformly
        //let beta = rand::random::<Fp2>();
        //To store the intermediate evaluations of the GGM tree
        //let mut v: Vec<Block> = vec![seed];
        self.sv1.push(seed);
        // To store the evaluations on the last level of the tree
        //let mut b: Vec<PprfRange> = Vec::new();
        // 2.b compute (s^i_{2j}, s^i_{2j+1}) = G(s^{i-1}_j)
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
                let s = self.sv1[i - 1 + j].clone();
                let (s0, s1) = prg_g(s);
                self.sv1.push(s0);
                self.sv1.push(s1);
            }
        }
        // 2.c compute (s^{l+1}_{2j}, s^{l+1}_{2j+1})
        for j in 0..2 ^ (Params::ELL) {
            let temp = self.sv1[Params::ELL + j].clone();
            let pair = prg_gprime(temp);
            self.sv2.push(pair);
        }
        Ok(())
    }
   

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        beta: (Fp, Fp),
        kpprf: Block
    ) -> Result<(), Error> {
    // 3. compute the left and right halves of intermediate levels
    let mut k0: Vec<Block> = Vec::new();
    let mut k1: Vec<Block> = Vec::new();
    let temp1 =  Block(*ZERO);
    let temp2 =  Block(*ZERO);
    //let _kt0:Block = v.iter().step_by(2).fold(temp1, |sum, &x| sum^x);
    // TODO: check this if works as desired.
    for i in 1..Params::ELL + 1 {
        for j in 0..2 ^ (i - 1) {
            let temp1 = temp1^self.sv1[i + j];
            let temp2 = temp2^self.sv1[i + j + 1];
        }
        k0.push(temp1);
        k1.push(temp2);
    }
    // 4. compute right half for the last level l+1.
    let k1lp1 = self.sv2.iter().fold(Block(*ZERO), |sum, &x| sum^x.1);
    ///5. Parallel OT calls
    use std::{os::unix::net::UnixStream, 
        io::{BufReader, BufWriter},
    };

    use crate::ot::Sender;
    let m0s_ = k0.clone();
    let m1s_ = k1.clone();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
    let mut rng = AesRng::new();
    let reader = BufReader::new(sender.try_clone().unwrap());
    let writer = BufWriter::new(sender);
    let mut channel = Channel::new(reader, writer);
    let mut ot = ChouOrlandiSender::init(&mut channel, &mut rng).unwrap();
    let ms = k0
        .into_iter()
        .zip(k1.into_iter())
        .collect::<Vec<(Block, Block)>>();
    ot.send(&mut channel, &ms, &mut rng).unwrap();
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = ChouOrlandiReceiver::init(&mut channel, &mut rng).unwrap();
    let bs:Vec<bool> = (0..Params::ELL).map(|_| rand::random::<bool>()).collect();
    let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
    handle.join().unwrap();
    for j in 0..Params::ELL {
    assert_eq!(result[j], if bs[j] { m0s_[j] } else { m1s_[j] });
    } 
    //6. compute correction value c
    let (s2j, _): (Vec<Fp2>, Vec<_>) = self.sv2.iter().cloned().unzip();
    //let t = s2j.iter().map(|(l, r)| (fold(temp1, |sum, &l| sum^l), r.fold(temp1, |sum, &x| sum^x)));
    let (left1, right1): (Vec<_>, Vec<_>) = s2j.iter().cloned().unzip();
    let lsum:Block = left1.iter().fold(Block(*ZERO), |sum, &x| Block(unsafe {_mm_add_epi64(sum.0, x.0)}));
    let rsum:Block = right1.iter().fold(Block(*ZERO), |sum, &x| Block(unsafe {_mm_add_epi64(sum.0, x.0)}));
    let l: Block = Block (unsafe {_mm_subs_epi16((beta.0).0, lsum.0)});
    let r: Block = Block (unsafe {_mm_subs_epi16((beta.1).0, rsum.0)});
    let c = (l, r);
    // 7. apply hash function.
    let mut hasher = Blake2b::new();
    let (l, r): (Vec<_>, Vec<_>) = self.sv2.iter().cloned().unzip();
    for i in 0..2 ^ (Params::ELL) {
    hasher.update(r[i]);
    }
    let hash = hasher.finalize();
    let gamma = hash.as_slice().try_into().unwrap();
    channel.write_block(&k1lp1)?;
    channel.write_block(&c.0)?;
    channel.write_block(&c.1)?;
    channel.write_block512(&gamma)?;
    channel.flush()?;
    Ok(())
        }
}



impl PprfReceiver for Receiver{
    type Msg = Block;
    fn init<C: AbstractChannel>(&mut self,
        channel: &mut C
    ) -> Result<Self, Error>{
        // Read hash value from the sender
        //let k1 = channel.read_block();
        //let kv = channel.read_blocks(Params::ELL+1).unwrap();
        //let hash = channel.read_block512().unwrap();
        //let c = (channel.read_block().unwrap(), channel.read_block().unwrap());
        //let alpha = rand::random::<Block>();
        let v = Vec::new();
        Ok(Self {rv:v})
    }
    
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        alpha: Block
    ) -> Option<(Vec<Block>, (Block, Block))> {
        //TODO: complete this definition
        //let kv = channel.read_blocks(Params::ELL+1).unwrap();
        let gamma = channel.read_block512().unwrap();
        let c = (channel.read_block().unwrap(), channel.read_block().unwrap());
        let k1lp1:Block = channel.read_block().unwrap();
        self.rv.push(k1lp1);
        /*let ks = (0..input1.len())
        .map(|i| {
            let k0 = input1[i].0;
            let k1 = input1[i].1;
            Ok((k0, k1))
        })
        .collect::<Result<Vec<(Block, Block)>, Error>>();*/
        // 8.(a)
        let mut kstar = puncturestar(self.rv.clone(), alpha);
        let kp = kstar.clone();
        // TODO: check if it is acually alpha || 0
        // 8.(b)
        let sv = fulleval(kstar, alpha);
        // 8.(c) compute w = c- sum s2j
        let (svl, svr) = (1..Params::N+1).filter(|&x| 
            Block(unsafe{_mm_set_epi32(0, 0, 0, x as i32)}) != alpha)
            .map(|i| sv[2*i]).unzip();
        let sum:Vec<Block>= vec![svl, svr].into_iter()
        .map(|x:Vec<Block>| x.into_iter().fold(Block(*ZERO), |sum, x| {Block(unsafe {_mm_add_epi64(sum.0, x.0)})})).collect();
        let w = (Block(unsafe {_mm_subs_epi16((c.0).0, sum[0].0)}), Block(unsafe {_mm_subs_epi16((c.1).0, sum[1].0)}));
        // 8.(d) compute hash function
        let mut hasher = Blake2b::new();
        let (l, r): (Vec<_>, Vec<_>) = sv.iter().cloned().unzip();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(r[i]);
        }
        let hash = hasher.finalize();
        let gamma_prime:Block512 = hash.as_slice().try_into().unwrap();
        //9. Check if hash values match. If yes, send out the puncture key kp and correction value w else abort.
        if gamma == gamma_prime {
            Some ((kp, w))
        } else { None }
    }
}


// PPRF related functions
pub fn keygen(lambda: Block) -> Block{
    let mut rng = AesRng::from_seed(lambda);
    let seed = rng.gen::<Block>();
    seed
}
pub fn puncturestar (keys: Vec<Block>, alpha: Block) -> Vec<Block> {
    // Given set of keys and alpha, outputs a punctured key.
    // TODO: fix this later
    let mut kstar:Vec<Block> = Vec::new();
    for i in 1..Params::ELL+2{
        let s = rand::random::<Block>();
        kstar.push(s);
    }
    kstar
}

pub fn fulleval (kstar: Vec<Block>, alpha: Block) -> Vec<(Block, Block)> {
    let mut s:Vec<(Block, Block)> = Vec::new();
    for i in 1..kstar.len(){
        if Block(unsafe {_mm_set_epi32(0, 0, 0, i as i32)}) == alpha{
            continue;
        }
        s.push(rand::random::<(Block, Block)>());
    }
    s
}