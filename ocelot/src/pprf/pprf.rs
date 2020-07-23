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
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Malicious};
use blake2::{Blake2b, Digest};
use std::{arch::x86_64::*, convert::TryInto, marker::PhantomData};
use ff::{Field};


/// Parameters for the mal-PPRF protocol
pub struct Params;
impl Params {
   // pub const LAMBDA: Block = Block(unsafe { _mm_setzero_si128() });
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


/// implement PprfSender for Sender

impl <OT: OtSender<Msg=Block> + Malicious, PPRF:PPRFTrait> PprfSender for Sender<OT, PPRF>{
    type Msg = Block;

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        mut beta: (Fp, Fp),
        kpprf: Block,
    ) -> Result<(), Error> {
         /// 1. Set the initial seed to kpprf
         self.sv1.push(kpprf);
         /// Use kpprf as a security parameter
         let mut rng = AesRng::from_seed(kpprf);
         /// 2.b Compute 2^i partial evaluations for all intermediate levels 1..l
         /// (s^i_{2j}, s^i_{2j+1}) = G(s^{i-1}_j).
         for i in 1..Params::ELL + 1 {
             for j in 0..2 ^ (i - 1) {
                 let s = self.sv1[i - 1 + j].clone();
                 let (s0, s1) = PPRF::prg_g(s, &mut rng);
                 self.sv1.push(s0);
                 self.sv1.push(s1);
             }
         }
         /// 2.c Compute the evaluations for the last level l+1
         /// (s^{l+1}_{2j}, s^{l+1}_{2j+1}).
         for j in 0..2 ^ (Params::ELL) {
             let temp = self.sv1[Params::ELL + j].clone();
             let pair = PPRF::prg_gprime(temp, &mut rng);
             self.sv2.push(pair);
         }
        /// 3. Compute the left and right halves of the intermediate levels.
        let mut k0: Vec<Block> = Vec::new();
        let mut k1: Vec<Block> = Vec::new();
        //let _kt0:Block = v.iter().step_by(2).fold(temp1, |sum, &x| sum^x);
        (1..Params::ELL + 1).into_iter().fold(Block(*ZERO), |sum, i| 
            {for j in 0..2 ^ (i - 1) {
                sum ^ self.sv1[i + j];
            }
            k0.push(sum);
            sum
             });
        (1..Params::ELL + 1).into_iter().fold(Block(*ZERO), |sum, i| 
        {for j in 0..2 ^ (i - 1) {
            sum ^ self.sv1[i + j + 1];
        }
        k1.push(sum);
        sum
        });
    
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
        Ok(())
    }
}

/// Implement PPRF Receiver for Receiver

impl <OT: OtReceiver<Msg = Block> + Malicious, PPRF:PPRFTrait> PprfReceiver for Receiver<OT, PPRF> {
    type Msg = Block;

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

