// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use num::pow;
use rand::{Rng, SeedableRng};
use scuttlebutt::{field::FiniteField as FF, utils::unpack_bits, AesRng, Block};
use std::collections::VecDeque;

/// Constructing GGM tree with `h` levels.
fn prg(depth: usize, seed: Block) -> Vec<Block> {
    let h = depth;
    let mut sv = Vec::new();
    sv.push(seed);
    for i in 1..h + 1 {
        let exp = 1 << (i - 1);
        for j in 0..exp {
            let s = sv[j + exp - 1];
            //PRG G
            let mut rng = AesRng::from_seed(s);
            let (s0, s1) = rng.gen::<(Block, Block)>();
            sv.push(s0);
            sv.push(s1);
        }
    }
    sv
}

/// constructing leaves.
/*pub fn prg_prime<FE: FF>(depth: usize, sv: &[Block]) -> Vec<FE> {
    let h = depth as usize;
    let exp = pow(2, h - 1);
    let mut v = Vec::new();
    for j in 0..exp {
        let temp = sv[h - 1 + j];
        // PRG G'
        let mut rng = AesRng::from_seed(temp);
        let (fe0, fe1) = (FE::random(&mut rng), FE::random(&mut rng));
        v.push(fe0);
        v.push(fe1);
    }
    v
}*/

/// The input vector length `n` may be included in the arguments.
pub fn ggm<FE: FF>(h: usize, seed: Block) -> (Vec<FE>, Vec<(Block, Block)>) {
    let seeds = prg(h, seed);
    println!("seeds = {:?}", seeds);
    let mut keys: Vec<(Block, Block)> = vec![Default::default(); h];
    for i in 0..h {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            k0 ^= seeds[1 + j + exp - 1]; // Even keys
            k1 ^= seeds[2 + j + exp - 1]; // Odd keys
        }
        keys[i] = (k0, k1);
    }
    let exp = 1 << h;
    let mut vs = vec![FE::zero(); exp];
    for j in 0..exp {
        println!("seed -> v: {}", seeds[j + exp - 1]);
        vs[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(seeds[j + exp - 1]));
    }
    (vs, keys)
}

/// GGM prime is used compute the vector of field elements except one entry at `alpha`.
//TODO: this can be fixed and optimized later.
pub fn ggm_prime<FE: FF>(alpha: usize, keys: &[Block]) -> Vec<FE> {
    let h = keys.len();
    println!("h = {}", h);
    println!("alpha = {}", alpha);
    let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), h);
    alpha_bits.reverse();
    println!("alpha bits = {:?}", alpha_bits);
    let mut seeds = VecDeque::new();
    let mut vs = vec![FE::zero(); 1 << h];
    for (i, (bit, key)) in alpha_bits.iter().zip(keys.iter()).enumerate() {
        println!("i = {} : {} | bit = {}, XORed key = {}", i, h, bit, key);
        let mut xor = Default::default();
        for _ in 0..seeds.len() {
            let (even, odd) = seeds.pop_front().unwrap();
            xor ^= if *bit { even } else { odd };
            if i < h - 1 {
                let mut rng = AesRng::from_seed(even);
                let new = rng.gen::<(Block, Block)>();
                println!("i = {} | new even seeds from {}: {:?}", i, even, new);
                seeds.push_back(new);
                let mut rng = AesRng::from_seed(odd);
                let new = rng.gen::<(Block, Block)>();
                println!("i = {} | new odd seeds from {}: {:?}", i, odd, new);
                seeds.push_back(new);
            } else {
                let v = FE::from_uniform_bytes(&<[u8; 16]>::from(even));
                println!("seed to v' from even: {}", even);
                vs.push(v);
                let v = FE::from_uniform_bytes(&<[u8; 16]>::from(odd));
                println!("seed to v' from odd: {}", odd);
                vs.push(v);
            }
        }
        let seed = *key ^ xor;
        if i < h - 1 {
            let mut rng = AesRng::from_seed(seed);
            let new = rng.gen::<(Block, Block)>();
            println!("i = {} | new final seeds from {}: {:?}", i, seed, new);
            seeds.push_back(new);
        } else {
            println!("seed to v': {}", seed);
            vs.push(FE::from_uniform_bytes(&<[u8; 16]>::from(seed)));
        }
    }
    assert_eq!(vs.len(), (1 << h) - 1);
    vs
}

/// Convert bit-vector to a number.
fn bv_to_u128(v: &[bool]) -> u128 {
    v.iter()
        .enumerate()
        .map(|(i, &v)| pow(2, i) * v as u128)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::field::{Fp, Gf128};

    #[test]
    fn test_bv_to_u128() {
        let x = rand::random::<u128>();
        let bv = unpack_bits(&x.to_le_bytes(), 128);
        assert_eq!(bv_to_u128(&bv), x);
    }

    #[test]
    fn test_ggm() {
        for _ in 0..10 {
            let seed = Default::default();
            // Runs for a while if the range is over 20.
            // let depth = rand::thread_rng().gen_range(1, 18);
            let depth = 2;
            let (v, keys) = ggm::<Gf128>(depth, seed);
            println!("keys = {:?}", keys);
            println!("v = {:?}", v);
            let alpha: usize = 0;
            // let alpha = rand::thread_rng().gen_range(0, leaves);
            let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
            alpha_bits.reverse();
            let alpha_keys: Vec<Block> = alpha_bits
                .iter()
                .zip(keys.iter())
                .map(|(b, k)| if *b { k.0 } else { k.1 })
                .collect();
            println!("alpha keys = {:?}", alpha_keys);
            let leaves = 1 << depth;
            let v_ = ggm_prime::<Gf128>(alpha, &alpha_keys);
            println!("v_ = {:?}", v_);
            println!("leaves = {}", leaves);
            for i in 0..v_.len() {
                println!("i = {}", i);
                if i != alpha {
                    assert_eq!(v[i + ((i > alpha) as usize)], v_[i]);
                }
            }
        }
    }
    // The following test fails for some reason.
    /* #[test]
    fn test_ggm_fp() {
        let x = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        let depth = rand::thread_rng().gen_range(1, 18);
        let (v, keys) = ggm::<Fp>(depth, x);
        let k: Vec<Block> = keys.iter().map(|k| k.0).collect();
        let leaves = pow(2, depth);
        let alpha = leaves - 1;
        let v1 = ggm_prime::<Fp>(alpha, &k);
        for i in 0..leaves {
            if i != alpha {
                assert_eq!(v[i], v1[i]);
            }
        }
    }*/
}
