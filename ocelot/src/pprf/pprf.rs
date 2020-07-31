// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Puncturable Pseudo-Random Function (PPRF) Trait
use crate::field::Fp;
use crate::pprf::vec_bool_u128;
use rand::*;
use scuttlebutt::{AesRng, Block};

use std::arch::x86_64::*;

pub type Fp2 = (Fp, Fp);
pub type PprfRange = (Fp2, Block);
pub type Fpstar = Fp;

// Define static variable
lazy_static! {
    static ref ZERO: __m128i = unsafe { _mm_setzero_si128() };
}

pub struct Params;
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 127;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2 ^ Params::ELL;
}

pub trait Pprf {
    // Key generation
    fn keygen(&self) -> Block {
        rand::random::<Block>()
    }

    // length doubling PRG G
    fn prg_g(&self, seed: Block) -> (Block, Block) {
        let mut rng = AesRng::from_seed(seed);
        rng.gen::<(Block, Block)>()
    }

    // PRG G': used to compute the PRF outputs on the last level of the tree.
    fn prg_gprime(&self, seed: Block) -> PprfRange {
        let mut rng = AesRng::from_seed(seed);
        rng.gen::<PprfRange>()
    }

    // Evaluates at given point x
    fn eval(&self, k: Block, x: Block) -> Block {
        let mut a_star: Vec<bool> = Vec::new();
        let _alpha = x;
        // Get Bit vector from x.
        for _i in 1..Params::ELL + 1 {
            let bit = _alpha.lsb();
            a_star.push(bit);
            _alpha.bitshift_right();
        }
        let mut res: Vec<Block> = Vec::new();
        for item in a_star.iter().skip(1).take(Params::ELL) {
            let tmp = k;
            if !item {
                let tmp = self.prg_g(tmp).0;
                res.push(tmp);
            } else {
                let tmp = self.prg_g(tmp).1;
                res.push(tmp);
            }
        }
        // Return the leaf K^l.
        res.pop().unwrap()
    }
    // Given key k and a point x outputs punctured key k{x}.
    fn puncture(&self, k: Block, x: Block) -> Vec<Block> {
        let mut a_star: Vec<bool> = Vec::new();
        let _alpha = x;
        // Get Bit vector from x
        for _i in 1..Params::ELL + 1 {
            let bit = _alpha.lsb();
            a_star.push(bit);
            _alpha.bitshift_right();
        }
        let mut res: Vec<Block> = Vec::new();
        for item in a_star.iter().skip(1).take(Params::ELL) {
            let tmp = k;
            if !item {
                let (k0, k1) = self.prg_g(tmp);
                let _tmp = k0;
                res.push(k1);
            } else {
                let (k0, k1) = self.prg_g(tmp);
                let _tmp = k1;
                res.push(k0);
            }
        }
        // Return all the other keys
        res
    }
    // Given punctured key k{x}, and a point x', returns either a fail or a vector of keys
    fn puncture_eval(&self, kx: Vec<Block>, x: Block, xprime: Block) -> Option<Block> {
        assert_eq!(self.puncture(self.keygen(), x), kx);
        if x == xprime {
            None
        } else {
            let mut _xbv: Vec<bool> = Vec::new();
            let mut _xpbv: Vec<bool> = Vec::new();
            let _xp = xprime;
            // Get Bit vector from x.
            for _i in 1..Params::ELL + 1 {
                let bit = x.lsb();
                let bitp = _xp.lsb();
                _xbv.push(bit);
                _xpbv.push(bitp);
                x.bitshift_right();
                _xp.bitshift_right();
            }
            let ind: Vec<usize> = (0.._xpbv.len()).filter(|&i| _xbv[i] != _xpbv[i]).collect();
            Some(self.eval(kx[ind[0]], xprime))
        }
    }
    //
    fn puncture_star(&self, keys: Vec<Block>, alpha: Block) -> Vec<Block> {
        // Given set of keys and alpha, outputs a punctured key.
        // the number of levels L actually depends on the security parameter LAMBDA
        // In other words, L cannot be more than LAMBDA =128
        // As defined in page 30.
        assert_eq!(keys.len(), Params::ELL + 1);
        let mut a_star: Vec<bool> = Vec::new();
        let _alpha = alpha;
        // Get Bit vector from alpha
        for _i in 1..Params::ELL + 1 {
            let bit = _alpha.lsb();
            a_star.push(bit);
            _alpha.bitshift_right();
        }
        // Set lth bit as 0
        a_star.push(false);
        // construct alpha_i^*s
        let mut ai_star: Vec<Vec<bool>> = Vec::new();
        for i in 1..Params::ELL + 2 {
            let mut av: Vec<bool> = Vec::new();
            for (j, item) in a_star.iter().enumerate().take(i) {
                if j == (i - 1) {
                    av.push(!*item);
                    break;
                }
                av.push(*item);
            }
            ai_star.push(av);
        }
        assert_eq!(ai_star.len(), Params::ELL + 1);
        let mut kstar: Vec<Block> = Vec::new();
        kstar.push(keys[0]);
        for i in 1..Params::ELL + 1 {
            for j in 0..2 ^ (i - 1) {
                let tmp: Vec<bool> = (0..ai_star[i].len())
                    .filter(|&x| x != i - 1)
                    .map(|y| ai_star[i][y])
                    .collect();
                if j == vec_bool_u128(tmp) as usize {
                    continue;
                }
                let s = kstar[i - 1 + j];
                let mut rng = AesRng::from_seed(s);
                //let (s0, s1) = PRG::prg_g(s);
                let (s0, s1) = rng.gen::<(Block, Block)>();
                kstar.push(s0);
                kstar.push(s1);
            }
        }
        let mut sv2: Vec<PprfRange> = Vec::new();
        for j in 0..2 ^ (Params::ELL) {
            if j == u128::from(alpha) as usize {
                continue;
            }
            let temp = kstar[Params::ELL + j];
            let pair = self.prg_gprime(temp);
            sv2.push(pair);
        }

        let mut salpha: Vec<Block> = Vec::new();
        for i in 1..Params::ELL + 2 {
            //2(b) compute
            let _abar = ai_star[i - 1].clone().pop().unwrap() as usize;
            let res = (0..2 ^ (i - 1))
                .filter(|&j| j as u128 != vec_bool_u128(ai_star[i - 1].clone()))
                .fold(Block(*ZERO), |sum, j| sum ^ kstar[2 * j + _abar]);
            salpha.push(res ^ keys[i]);
        }
        assert_eq!(salpha.len(), Params::ELL + 1);
        salpha
    }

    fn full_eval(&self, kstar: Vec<Block>, alpha: Block) -> Vec<PprfRange> {
        assert_eq!(kstar.len(), Params::ELL + 1);
        // Left shift alpha to make it even.
        let _aeven = alpha.bitshift_left();
        let mut s: Vec<PprfRange> = Vec::new();
        for i in 1..2 * Params::N + 1 {
            let ib: Block = Block::from(i as u128);
            if ib != _aeven {
                continue;
            }
            s.push(self.prg_gprime(ib));
        }
        assert_eq!(s.len(), 2 * Params::N - 1);
        s
    }
}
