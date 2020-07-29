// -*- mode: rust; -*-
//
// This file is part of ocelot.

// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.13 page 25)

#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    field::{Fp, FpRepr},
    ot::{Receiver as OtReceiver, Sender as OtSender},
    pprf::{Fp2, PprfReceiver, PprfSender, PPRF as PPRFTrait},
};
use rand::{Rng, SeedableRng, RngCore};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Malicious, SemiHonest};
use blake2::{Blake2b, Digest};
use std::{arch::x86_64::*, convert::TryInto, marker::PhantomData};
use ff::{Field};


/// Parameters for the mal-PPRF protocol
pub struct Params;
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2 ^ Params::ELL;
}

#[allow(dead_code)]
type PprfRange = (Fp2, Block);

// Define static variable
lazy_static! {
    static ref ZERO: __m128i = unsafe { _mm_setzero_si128() };
}

/// A PPRF Sender.
#[derive(Debug)]
pub struct Sender<OT: OtSender + Malicious, PPRF:PPRFTrait> {
    _ot: PhantomData<OT>,
    _pprf: PhantomData<PPRF>,
    /// To store partial evaluations of the intermediate levels.
    sv1: Vec<Block>,
    /// To store partial evaluation of the last level l+1.
    sv2: Vec<PprfRange>,
}


/// A PPRF Receiver.
#[derive(Debug)]
struct Receiver<OT: OtReceiver + Malicious, PPRF:PPRFTrait> {
    _ot: PhantomData<OT>,
    _pprf: PhantomData<PPRF>,
    /// A vector to store all the evaluations s_j suchthat j is not equal to alpha||0.
    rv: Vec<Block>,
}

/// Write a `Fp` to the channel.
#[inline(always)]
pub fn write_fp<C:AbstractChannel>(channel: &mut C, s: Fp) -> std::io::Result<()> {
    for i in 0..((s.0).0).len(){
        channel.write_u64(((s.0).0)[i])?;
    }
    Ok(())
}

/// Read a `Fp` from the channel.
#[inline(always)]
pub fn read_fp<C:AbstractChannel>(channel: &mut C) -> std::io::Result<Fp> {
    let mut data = [0u64; 4];
    for i in 0..4{
        data[i]=channel.read_u64()?;
    }
    Ok(Fp(FpRepr(data)))
}
/// implement PPRFTrait for Sender.

impl <OT: OtSender<Msg=Block> + Malicious, PPRF:PPRFTrait> PPRFTrait for Sender<OT, PPRF>{
    fn prg_g(seed: Block) -> (Block, Block) {
        let mut rng = AesRng::from_seed(seed);
        let pair = rng.gen::<(Block, Block)>();
        pair
    }

    fn prg_gprime(seed: Block) -> PprfRange {
        let mut rng = AesRng::from_seed(seed);
        let triple = rng.gen::<PprfRange>();
        triple
    }

    fn puncture_star(keys:Vec<Block>, alpha:Block) -> Vec<Block>{
    // Given set of keys and alpha, outputs a punctured key.
    // TODO: Replace this with the actual definition.
    let mut kstar: Vec<Block> = Vec::new();
    for i in 1..Params::ELL + 2 {
        let s = rand::random::<Block>();
        kstar.push(s);
    }
    kstar

    }
    
    fn full_eval(kstar: Vec<Block>, alpha: Block) -> Vec<PprfRange>{
        let mut s: Vec<PprfRange> = Vec::new();
        for i in 1..kstar.len() {
            if Block(unsafe { _mm_set_epi32(0, 0, 0, i as i32) }) == alpha {
                continue;
            }
            //TODO: replace this with the actual definition.
            s.push(rand::random::<PprfRange>());
        }
        s
    
    }
}

/// implement PPRFTrait for Receiver.

impl <OT: OtReceiver<Msg=Block> + Malicious, PPRF:PPRFTrait> PPRFTrait for Receiver<OT, PPRF>{
    fn prg_g(seed: Block) -> (Block, Block) {
        let mut rng = AesRng::from_seed(seed);
        let pair = rng.gen::<(Block, Block)>();
        pair
    }

    fn prg_gprime(seed: Block) -> PprfRange {
        let mut rng = AesRng::from_seed(seed);
        let triple = rng.gen::<PprfRange>();
        triple
    }

    fn puncture_star(keys:Vec<Block>, alpha:Block) -> Vec<Block>{
    // Given set of keys and alpha, outputs a punctured key.
    /// the number of levels L actually depends on the security parameter LAMBDA
    /// In other words, L cannot be more than LAMBDA =128
    // TODO: Replace this with the actual definition.
    assert_eq!(keys.len(), Params::ELL+1);
    let mut alpha_star:Vec<Block> = Vec::new();
    let alpha_lp1:Block = Block(*ZERO);
    for i in 1..Params::ELL+1{
        let alpha1 = alpha.lsb();
        let a = Block::from(u128::from(!alpha.lsb()));
        alpha_star.push(value: T)
        
    }
    let mut kstar: Vec<Block> = Vec::new();
    for i in 1..Params::ELL + 2 {
        let s = rand::random::<Block>();
        kstar.push(s);
    }
    kstar

    }
    
    fn full_eval(kstar: Vec<Block>, alpha: Block) -> Vec<PprfRange>{
        let mut s: Vec<PprfRange> = Vec::new();
        for i in 1..kstar.len() {
            if Block(unsafe { _mm_set_epi32(0, 0, 0, i as i32) }) == alpha {
                continue;
            }
            //TODO: replace this with the actual definition.
            s.push(rand::random::<PprfRange>());
        }
        s
    
    }
}
/// implement PprfSender for Sender

impl <OT: OtSender<Msg=Block> + Malicious, PPRF:PPRFTrait> PprfSender for Sender<OT, PPRF>{
    type Msg = Block;
    fn init() -> Result<Self, Error>{
        let v0 = Vec::new();
        let v1 = Vec::new();
      Ok(Self{_ot:PhantomData::<OT>, _pprf:PhantomData::<PPRF>, sv1:v0, sv2:v1})
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        mut beta: (Fp, Fp),
    ) -> Result<Block, Error> {
         /// 1. Set the initial seed to kpprf.
         let kpprf = rand::random::<Block>();
         self.sv1.push(kpprf);
         /// Use kpprf as a security parameter
         let mut rng = AesRng::from_seed(kpprf);
         /// 2.b Compute 2^i partial evaluations for all intermediate levels 1..l
         /// (s^i_{2j}, s^i_{2j+1}) = G(s^{i-1}_j).
         for i in 1..Params::ELL + 1 {
             for j in 0..2 ^ (i - 1) {
                 let s = self.sv1[i - 1 + j].clone();
                 let (s0, s1) = PPRF::prg_g(s);
                 self.sv1.push(s0);
                 self.sv1.push(s1);
             }
         }
         /// 2.c Compute the evaluations for the last level l+1
         /// (s^{l+1}_{2j}, s^{l+1}_{2j+1}).
         for j in 0..2 ^ (Params::ELL) {
             let temp = self.sv1[Params::ELL + j].clone();
             let pair = PPRF::prg_gprime(temp);
             self.sv2.push(pair);
         }
        /// 3. Compute the left and right halves of the intermediate levels.
        self.sv1.pop();
        let elts_even: Vec<Block> = (0..self.sv1.len()).into_iter().step_by(2).map(|i| self.sv1[i]).collect();
        let elts_odd: Vec<Block> = (0..self.sv1.len()).into_iter().skip(1).step_by(2).map(|i| self.sv1[i]).collect();
        let zipevals: Vec<(Block, Block)> = elts_even.into_iter().zip(elts_odd).collect();
        let mut k0: Vec<Block> = Vec::new();
        let mut k1: Vec<Block> = Vec::new();
        for i in 1..Params::ELL + 1{
            let mut res0 = Block(*ZERO);
            let mut res1 = Block(*ZERO); 
            for j in 0..2 ^ (i - 1){
              res0= res0^zipevals[j+2 ^ (i - 1)-1].0;
              res1= res1^zipevals[j+2 ^ (i - 1)-1].1;
            }
            k0.push(res0);
            k1.push(res1);
        }
        /// 4. Compute right half for the last level l+1.
        let k1lp1 = self.sv2.iter().fold(Block(*ZERO), |sum, &x| sum ^ x.1);
        /// 5. 
        let mut ot = OT::init(channel, &mut rng).unwrap();
        let ms = k0
                .into_iter()
                .zip(k1.into_iter())
                .collect::<Vec<(Block, Block)>>();
        ot.send(channel, &ms, &mut rng)?;
        /// 6. Compute the correction value c.
        let (s2j, _): (Vec<Fp2>, Vec<Block>) = self.sv2.iter().cloned().unzip();
        //let t = s2j.iter().map(|(l, r)| (fold(temp1, |sum, &l| sum^l), r.fold(temp1, |sum, &x| sum^x)));
        let (left1, right1): (Vec<Fp>, Vec<Fp>) = s2j.iter().cloned().unzip();
        let lsum: Fp = left1.iter().fold(Field::zero(), |mut sum, &x| {sum.add_assign(&x); sum});
        let rsum: Fp = right1.iter().fold(Field::zero(), |mut sum, &x| {sum.add_assign(&x); sum});
        /// subtracting from beta
        (beta.0).sub_assign(&lsum);
        (beta.1).sub_assign(&rsum);
        /// 7. Apply hash function.
        let mut hasher = Blake2b::new();
        let (_, r): (Vec<Fp2>, Vec<Block>) = self.sv2.iter().cloned().unzip();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(r[i]);
        }
        let hash = hasher.finalize();
        let gamma = hash.as_slice().try_into().unwrap();
        channel.write_block(&k1lp1)?;
        write_fp(channel, beta.0)?;
        write_fp(channel, beta.1)?;
        channel.write_block512(&gamma)?;
        channel.flush()?;
        Ok(kpprf)
    }
}

/// Implement PPRF Receiver for Receiver

impl <OT: OtReceiver<Msg = Block> + Malicious, PPRF:PPRFTrait> PprfReceiver for Receiver<OT, PPRF> {
    type Msg = Block;
    fn init() -> Result<Self, Error>{
        let v0 = Vec::new();
      Ok( Self{_ot:PhantomData::<OT>, _pprf:PhantomData::<PPRF>, rv:v0})
    }

    fn receive<C:AbstractChannel>(
        &mut self,
        channel: &mut C,
        alpha: Block
    ) -> Option<(Vec<Block>, (Fp, Fp))> 
    {
        let mut rng = AesRng::from_seed(Block(*ZERO));
        let mut ot = OT::init(channel, & mut rng).unwrap();
        let bv = rng.gen::<[bool; Params::ELL]>();
        let mut ks = ot.receive(channel, &bv, & mut rng).unwrap();
        let gamma:Block512 = channel.read_block512().unwrap();
        let mut w:(Fp, Fp) = (read_fp(channel).unwrap(), read_fp(channel).unwrap());
        let k1lp1: Block = channel.read_block().unwrap();
        self.rv.append(&mut ks);
        self.rv.push(k1lp1);
        /// 8.(a) Apply puncturestar on the Kis and alpha.
        let kstar = PPRF::puncture_star(self.rv.clone(), alpha);
        let kp = kstar.clone();
        /// 8.(b) Apply fulleval on kstar and alpha||0.
        /// TODO: check here
        let sv = PPRF::full_eval(kstar, alpha);
        // 8.(c) compute w = c- sum s2j
        let (svl, _):(Vec<Fp2>, Vec<Block>) = (1..Params::N + 1)
            .filter(|&x| Block(unsafe { _mm_set_epi32(0, 0, 0, x as i32) }) != alpha)
            .map(|i| sv[2 * i])
            .unzip();
        let (svl0, svl1):(Vec<Fp>, Vec<Fp>) = svl.into_iter().unzip();
        let lsum:Fp = svl0.iter().fold(Field::zero(), |mut sum, &x| { sum.add_assign(&x); sum });
        let rsum:Fp = svl1.iter().fold(Field::zero(), |mut sum, &x| { sum.add_assign(&x); sum });
        (w.0).sub_assign(&lsum);
        (w.1).sub_assign(&rsum);
        // 8.(d) compute hash function
        let mut hasher = Blake2b::new();
        let (_, r): (Vec<_>, Vec<_>) = sv.iter().cloned().unzip();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(r[i]);
        }
        let hash = hasher.finalize();
        let gamma_prime: Block512 = hash.as_slice().try_into().unwrap();
        //9. Check if hash values match. If yes, send out the puncture key kp and correction value w else abort.
        if gamma == gamma_prime {
            Some((kp, w))
        } else {
            None
        }
    }
}

impl <OT:OtSender+Malicious, PPRF:PPRFTrait> std::fmt::Display for Sender<OT, PPRF> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PPRF Sender")
    }
}

impl <OT:OtReceiver+Malicious, PPRF:PPRFTrait> std::fmt::Display for Receiver<OT, PPRF> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result{
        write!(f, "PPRF Receiver")
    }
}


//impl <OT: OtSender<Msg=Block> + SemiHonest, PPRF:PPRFTrait> SemiHonest for Sender<OT,PPRF> {}
//impl <OT: OtSender<Msg=Block> + Malicious, PPRF:PPRFTrait> Malicious for Sender<OT,PPRF> {}
//impl <OT: OtSender<Msg=Block> + SemiHonest, PPRF:PPRFTrait> SemiHonest for Receiver<OT,PPRF> {}
//impl <OT: OtSender<Msg=Block> + Malicious, PPRF:PPRFTrait> Malicious for Receiver<OT,PPRF> {}

/// Add few test cases

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pprf::*;
    use scuttlebutt::{AesRng, Channel};
    use crate::ot::{ChouOrlandiSender, chou_orlandi::Sender, chou_orlandi::Receiver, ChouOrlandiReceiver};
    use std::{
        fmt::Display,
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    
    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn test_ot<OTSender: OtSender<Msg=Block>+ Malicious, OTReceiver: OtReceiver<Msg=Block>+ Malicious, PPRF:PPRFTrait>() {
        let alphas = rand::random::<Block>();
        let beta = rand::random::<(Fp, Fp)>();
        let _alphas = alphas.clone();
        let _beta = beta.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut pprf:pprf::Sender<OTSender, PPRF> = PprfSender::init().unwrap();
            let key:Block = pprf.send(&mut channel, _beta).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut pprf:pprf::Receiver<OTReceiver, PPRF> = PprfReceiver::init().unwrap();
        let result = pprf.receive(&mut channel, _alphas).unwrap();
        handle.join().unwrap();
        // TODO: Fix this after an instantiation of PPRF Trait
       assert_eq!(result.1, _beta)
    }

    #[test]
    fn test_pprf() {
        //test_ot<chou_orlandi::Sender::<Msg=Block>,chou_orlandi::Receiver::<Msg=Block>,PPRF>();
    }
}
