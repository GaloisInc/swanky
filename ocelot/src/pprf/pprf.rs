// -*- mode: rust; -*-
//
// This file is part of ocelot.

// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.13 page 25)

#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(unused_doc_comments)]

use crate::{
    errors::Error,
    ot::{ChouOrlandiReceiver, ChouOrlandiSender, Receiver as OtReceiver, Sender as OtSender},
    pprf::{BitVec, Fp2, PprfReceiver, PprfSender},
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Channel, Malicious, SemiHonest};
use super::Fp;
use blake2::{Blake2b, Blake2s, Digest};
use hex_literal::hex;
use std::{arch::x86_64::*, convert::TryInto};

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
pub struct Sender {
    /// To store partial evaluations of the intermediate levels.
    sv1: Vec<Block>,
    /// To store partial evaluation of the last level l+1.
    sv2: Vec<PprfRange>,
}

impl Sender {
    pub fn new() -> Sender {
        Sender {
            sv1: Vec::new(),
            sv2: Vec::new(),
        }
    }
}

/// A PPRF Receiver.
#[derive(Debug)]
struct Receiver {
    /// A vector to store all the evaluations s_j suchthat j is not equal to alpha||0.
    rv: Vec<Block>,
}

/// legnth-doubling PRG G.
#[allow(dead_code)]
fn prg_g(seed: Block) -> (Block, Block) {
    /// Generate RNG using seed.
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
/// Change this later
///
///
use crate::field::FpRepr;
fn add_fp(a: Fp, b: Fp) -> Fp {
    let mut z: [u64; 4] = [0, 0, 0, 0];
    for (i, (aval, bval)) in ((a.0).0).iter().zip(&(b.0).0).enumerate() {
        z[i] = aval + bval;
    }
    Fp(FpRepr(z))
}

fn sub_fp(a: Fp, b: Fp) -> Fp {
    let mut z: [u64; 4] = [0, 0, 0, 0];
    for (i, (aval, bval)) in ((a.0).0).iter().zip(&(b.0).0).enumerate() {
        z[i] = aval - bval;
    }
    Fp(FpRepr(z))
}

/// Write a `Fp` to the channel.
#[inline(always)]
fn write_fp<C:AbstractChannel>(channel: &mut C, s: Fp) -> std::io::Result<()> {
    for i in 0..((s.0).0).len(){
        channel.write_u64(((s.0).0)[i])?;
    }
    Ok(())
}

/// Read a `Fp` from the channel.
#[inline(always)]
fn read_fp<C:AbstractChannel>(channel: &mut C) -> std::io::Result<Fp> {
    let mut data = [0u64; 4];
    for i in 0..4{
        data[i]=channel.read_u64()?;
    }
    Ok(Fp(FpRepr(data)))
}


/// implement PprfSender for Sender

impl PprfSender for Sender {
    type Msg = Block;
    fn init(&mut self) -> Result<(), Error> {
        /// Sampling the key kpprf.
        let seed = rand::random::<Block>();
        self.sv1.push(seed);
        /// 2.b compute (s^i_{2j}, s^i_{2j+1}) = G(s^{i-1}_j).
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
                let s = self.sv1[i - 1 + j].clone();
                let (s0, s1) = prg_g(s);
                self.sv1.push(s0);
                self.sv1.push(s1);
            }
        }
        /// 2.c compute (s^{l+1}_{2j}, s^{l+1}_{2j+1}).
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
        kpprf: Block,
    ) -> Result<(), Error> {
        /// 3. compute the left and right halves of intermediate levels.
        let mut k0: Vec<Block> = Vec::new();
        let mut k1: Vec<Block> = Vec::new();
        let temp1 = Block(*ZERO);
        let temp2 = Block(*ZERO);
        //let _kt0:Block = v.iter().step_by(2).fold(temp1, |sum, &x| sum^x);
        // TODO: check this if works as desired.
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
                let temp1 = temp1 ^ self.sv1[i + j];
                let temp2 = temp2 ^ self.sv1[i + j + 1];
            }
            k0.push(temp1);
            k1.push(temp2);
        }
        /// 4. compute right half for the last level l+1.
        let k1lp1 = self.sv2.iter().fold(Block(*ZERO), |sum, &x| sum ^ x.1);
        ///5. Parallel OT calls
        use std::{
            io::{BufReader, BufWriter},
            os::unix::net::UnixStream,
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
        let bs: Vec<bool> = (0..Params::ELL).map(|_| rand::random::<bool>()).collect();
        let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
        handle.join().unwrap();
        for j in 0..Params::ELL {
            assert_eq!(result[j], if bs[j] { m0s_[j] } else { m1s_[j] });
        }
        /// 6. compute correction value c.
        let (s2j, _): (Vec<Fp2>, Vec<Block>) = self.sv2.iter().cloned().unzip();
        //let t = s2j.iter().map(|(l, r)| (fold(temp1, |sum, &l| sum^l), r.fold(temp1, |sum, &x| sum^x)));
        let (left1, right1): (Vec<Fp>, Vec<Fp>) = s2j.iter().cloned().unzip();

        use ff::*;
        let fpzero: Fp = Fp(FpRepr([0, 0, 0, 0]));
        let lsum: Fp = left1.iter().fold(fpzero, |sum, &x| add_fp(sum, x));
        let rsum: Fp = right1.iter().fold(fpzero, |sum, &x| add_fp(sum, x));

        let l: Fp = sub_fp(beta.0, lsum);
        let r: Fp = sub_fp(beta.1, rsum);
        let c = (l, r);
        /// 7. apply hash function.
        let mut hasher = Blake2b::new();
        let (_, r): (Vec<Fp2>, Vec<Block>) = self.sv2.iter().cloned().unzip();
        for i in 0..2 ^ (Params::ELL) {
            hasher.update(r[i]);
        }
        let hash = hasher.finalize();
        let gamma = hash.as_slice().try_into().unwrap();
        channel.write_block(&k1lp1)?;
        write_fp(&mut channel, c.0)?;
        write_fp(&mut channel, c.1)?;
        channel.write_block512(&gamma)?;
        channel.flush()?;
        Ok(())
    }
}


impl PprfReceiver for Receiver {
    type Msg = Block;
    fn init<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Self, Error> {
        let v = Vec::new();
        Ok(Self { rv: v })
    }

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        alpha: Block,
    ) -> Option<(Vec<Block>, (Fp, Fp))> {
        let gamma:Block512 = channel.read_block512().unwrap();
        let c:(Fp, Fp) = (read_fp(channel).unwrap(), read_fp(channel).unwrap());
        let k1lp1: Block = channel.read_block().unwrap();
        self.rv.push(k1lp1);
        
        /// 8.(a) Apply puncturestar on the Kis and alpha.
        let mut kstar = puncturestar(self.rv.clone(), alpha);
        let kp = kstar.clone();
        /// 8.(b) Apply fulleval on kstar and alpha||0.
        let sv = fulleval(kstar, alpha);
        // 8.(c) compute w = c- sum s2j
        let (svl, svr):(Vec<Fp2>, Vec<Block>) = (1..Params::N + 1)
            .filter(|&x| Block(unsafe { _mm_set_epi32(0, 0, 0, x as i32) }) != alpha)
            .map(|i| sv[2 * i])
            .unzip();
        let (svl0, svl1):(Vec<Fp>, Vec<Fp>) = svl.into_iter().unzip();
        let fpzero: Fp = Fp(FpRepr([0, 0, 0, 0]));
        let lsum:Fp = svl0.iter().fold(fpzero, |sum, &x| add_fp(sum, x));
        let rsum:Fp = svl1.iter().fold(fpzero, |sum, &x| add_fp(sum, x));
    
        let w = (sub_fp(c.0, lsum), sub_fp(c.1, rsum));
        // 8.(d) compute hash function
        let mut hasher = Blake2b::new();
        let (l, r): (Vec<_>, Vec<_>) = sv.iter().cloned().unzip();
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

// PPRF related functions
pub fn keygen(lambda: Block) -> Block {
    let mut rng = AesRng::from_seed(lambda);
    let seed = rng.gen::<Block>();
    seed
}
pub fn puncturestar(keys: Vec<Block>, alpha: Block) -> Vec<Block> {
    // Given set of keys and alpha, outputs a punctured key.
    // TODO: Replace this with the actual definition.
    let mut kstar: Vec<Block> = Vec::new();
    for i in 1..Params::ELL + 2 {
        let s = rand::random::<Block>();
        kstar.push(s);
    }
    kstar
}

pub fn fulleval(kstar: Vec<Block>, alpha: Block) -> Vec<PprfRange> {
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
