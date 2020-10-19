// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use rand::{Rng, SeedableRng};
use scuttlebutt::{field::FiniteField, utils::unpack_bits, AesRng, Block};

/// Returns dot product of two vectors.
pub fn dot_product<'a, FE: FiniteField, A: Iterator<Item = &'a FE>, B: Iterator<Item = &'a FE>>(
    x: A,
    y: B,
) -> FE {
    x.zip(y).map(|(u, v)| *u * *v).sum()
}

/// Construct GGM tree with `h` levels and return the node values (a.k.a seeds). Although, the
/// last level seeds to be of type `FE`, we keep them in the form of `Block` type as we need to
/// call do OT calls on them.
fn prg(depth: usize, seed: Block) -> Vec<Block> {
    let h = depth;
    let mut sv = Vec::new(); // seed vector
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
    //println!("seeds in prg={:?}", sv);
    sv
}

/// constructing leaves.
/*pub fn prg_prime<FE: FiniteField>(depth: usize, sv: &[Block]) -> Vec<FE> {
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

/// Given a depth and a seed, `ggm` returns OT keys along with a vector of field
/// elements that represent seeds of the last level.
/*pub fn ggm<FE: FiniteField>(depth: usize, seed: Block) -> (Vec<FE>, Vec<(Block, Block)>) {
    let seeds = prg(depth, seed);
    // println!("seeds = {:?}", seeds);
    let mut keys: Vec<(Block, Block)> = vec![Default::default(); depth];
    for (i, item) in keys.iter_mut().enumerate().take(depth) {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            println!("seeds_in ggm={:?}",seeds[1 + j + exp - 1]);
            k0 ^= seeds[1 + j + exp - 1]; // Even keys
            k1 ^= seeds[2 + j + exp - 1]; // Odd keys
        }
        *item = (k0, k1);
    }
    let exp = 1 << depth;
    let mut vs = vec![FE::ZERO; exp];
    for j in 0..exp {
        vs[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(seeds[j + exp - 1]));
        //println!("seeds_in_ggm={:?}", seeds[j + exp - 1]);
    }

    println!("seeds_in_ggm={:?}", seeds);
    (vs, keys)
}*/

pub fn ggm<FE: FiniteField>(depth: usize, seed: Block) -> (Vec<FE>, Vec<(Block, Block)>) {
    println!("h={}", depth);
    let sv = prg(depth, seed);
    println!("sv={:?}", sv);
    let even_seeds: Vec<Block> = sv.iter().skip(1).step_by(2).copied().collect(); // skip root node
    let odd_seeds: Vec<Block> = sv.iter().skip(2).step_by(2).copied().collect(); // skip root node
    let mut keys: Vec<(Block, Block)> = vec![Default::default(); depth];
    for (i, item) in keys.iter_mut().enumerate().take(depth) {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            k0 ^= even_seeds[exp + j - 1];
            k1 ^= odd_seeds[exp + j - 1];
        }
        *item = (k0, k1);
    }
    let exp = 1 << depth;
    println!("sv_in_ggm={:?}", sv);
    let mut vs: Vec<FE> = vec![FE::ZERO; exp];
    for j in 0..exp {
        println!("sv[exp + j - 1]={:?}", sv[exp + j - 1]);
        vs[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(sv[exp + j - 1]));
    }
    (vs, keys)
}

/// Given alpha and OTs (received based on the choice vector representing alpha complement),
/// GGM prime outputs the vector of field elements which supposed have the length equal to
/// the number of OTs minus 1.
//TODO: this can be fixed and optimized later.
/*pub fn ggm_prime<FE: FiniteField>(alpha: usize, keys: &[Block]) -> Vec<FE> {
    let h = keys.len();
    println!("h = {}", h);
    println!("alpha = {}", alpha);
    let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), h);
    alpha_bits.reverse();
    println!("alpha bits = {:?}", alpha_bits);
    let mut seeds = VecDeque::new();
    let mut vs = vec![];
    for (i, (bit, key)) in alpha_bits.iter().zip(keys.iter()).enumerate() {
        println!("i = {} : {} | bit = {}, XORed key = {}", i, h, bit, key);
        seeds.push_back((ZERO, key));
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
}*/

/// GGM prime is used compute the vector of field elements except a path b1..bn where b1 represents msb of alpha.
pub fn ggm_prime<FE: FiniteField>(alpha: usize, keys: &[Block]) -> Vec<FE> {
    let depth = keys.len();
    let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), depth);
    // To get MSB as first elt.
    alpha_bits.reverse();
    let leaves = 1 << depth;
    let mut sv: Vec<Block> = vec![Default::default(); 2 * leaves - 1]; // to store all seeds up to level depth
    let mut vs = vec![FE::ZERO; leaves];
    sv[1 + !alpha_bits[0] as usize] = keys[0];
    for i in 2..depth + 1 {
        let exp = 1 << (i - 1) as usize; // number of nodes in the prev. level.
        let exp_idx = 1 << i; // starting insertion position at the currrent level.
        for j in 0..exp {
            if sv[exp + j - 1] != Default::default() {
                let s = sv[exp + j - 1];
                let mut rng = AesRng::from_seed(s);
                let (s0, s1) = rng.gen::<(Block, Block)>();
                sv[2 * j + exp_idx - 1] = s0; // Even node
                sv[2 * j + exp_idx] = s1; // Odd node
            }
        }
        // let b1..bi-1 (b1 is MSB) be the bit representation of alpha up to the previous level
        // Then the insertion node at the current node would be b1..bi-1comp(bi).
        let mut tmp = alpha_bits.clone();
        tmp.truncate(i - 1);
        let ai_comp = !alpha_bits[i - 1];
        tmp.push(ai_comp);
        tmp.reverse();
        let ai_star = bv_to_num(&tmp); // node number at the current level
        let s_alpha = (0..exp).fold(Default::default(), |mut sum: Block, j| {
            sum ^= sv[exp_idx + 2 * j + ai_comp as usize - 1];
            sum
        });
        sv[exp_idx + ai_star as usize - 1] = s_alpha ^ keys[i - 1];
    }
    for j in 0..leaves {
        vs[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(sv[leaves + j - 1]));
    }
    vs
}

/// Convert bit-vector to a number.
fn bv_to_num(v: &[bool]) -> usize {
    v.iter()
        .enumerate()
        .map(|(i, &v)| (1 << i) * v as usize)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::field::{F61p, Fp, Gf128, F2};

    #[test]
    fn test_bv_to_num() {
        let x = rand::random::<usize>();
        let bv = unpack_bits(&x.to_le_bytes(), 64);
        assert_eq!(bv_to_num(&bv), x);
    }

    #[test]
    fn test_ggm_gf128() {
        for _ in 0..10 {
        let seed = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        // depth has to be atleast 2.
        let depth = rand::thread_rng().gen_range(2, 14);
        let (v, keys) = ggm::<Gf128>(depth, seed);
        println!("keys = {:?}", keys);
        println!("v = {:?}", v);
        let leaves = (1 << depth) - 1;
        println!("leaves={}", leaves);
        let alpha: usize = rand::thread_rng().gen_range(1, leaves);
        println!("alpha={}", alpha);
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        println!("alpha_bits = {:?}", alpha_bits);
        alpha_bits.reverse();
        println!("alpha_bits_rev = {:?}", alpha_bits);
        let alpha_keys: Vec<Block> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        println!("alpha keys = {:?}", alpha_keys);
        let leaves = 1 << depth;
        let v_ = ggm_prime::<Gf128>(alpha, &alpha_keys);
        println!("v_ = {:?}", v_);
        println!("leaves = {}", leaves);
        for i in 0..v_.len() {
            println!("i = {}", i);
            if i != alpha {
                assert_eq!(v[i], v_[i]);
            }
        }
    }
    }

    #[test]
    fn test_ggm_f2() {
        for _ in 0..10 {
        let seed = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        // depth has to be atleast 2.
        let depth = rand::thread_rng().gen_range(2, 14);
        let (v, keys) = ggm::<F2>(depth, seed);
        println!("keys = {:?}", keys);
        println!("v = {:?}", v);
        let leaves = (1 << depth) - 1;
        println!("leaves={}", leaves);
        let alpha: usize = rand::thread_rng().gen_range(1, leaves);
        println!("alpha={}", alpha);
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        println!("alpha_bits = {:?}", alpha_bits);
        alpha_bits.reverse();
        println!("alpha_bits_rev = {:?}", alpha_bits);
        let alpha_keys: Vec<Block> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        println!("alpha keys = {:?}", alpha_keys);
        let leaves = 1 << depth;
        let v_ = ggm_prime::<F2>(alpha, &alpha_keys);
        println!("v_ = {:?}", v_);
        println!("leaves = {}", leaves);
        for i in 0..v_.len() {
            println!("i = {}", i);
            if i != alpha {
                assert_eq!(v[i], v_[i]);
            }
        }
    }
    }

    #[test]
    fn test_ggm_fp() {
        for _ in 0..10 {
        let seed = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        // depth has to be atleast 2.
        let depth = rand::thread_rng().gen_range(2, 10);
        //let depth = 2;
        let (v, keys) = ggm::<Fp>(depth, seed);
        println!("keys = {:?}", keys);
        println!("v = {:?}", v);
        let leaves = (1 << depth) - 1;
        println!("leaves={}", leaves);
        let alpha: usize = rand::thread_rng().gen_range(1, leaves);
        println!("alpha={}", alpha);
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        println!("alpha_bits = {:?}", alpha_bits);
        alpha_bits.reverse();
        println!("alpha_bits_rev = {:?}", alpha_bits);
        let alpha_keys: Vec<Block> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        println!("alpha keys = {:?}", alpha_keys);
        let leaves = 1 << depth;
        let v_ = ggm_prime::<Fp>(alpha, &alpha_keys);
        println!("v_ = {:?}", v_);
        println!("leaves = {}", leaves);
        for i in 0..v_.len() {
            println!("i = {}", i);
            if i != alpha {
                assert_eq!(v[i], v_[i]);
            }
        }
    }
    }

    #[test]
    fn test_ggm_f61p() {
        for _ in 0..10 {
        let seed = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        // depth has to be atleast 2.
        let depth = rand::thread_rng().gen_range(2, 14);
        let (v, keys) = ggm::<F61p>(depth, seed);
        println!("keys = {:?}", keys);
        println!("v = {:?}", v);
        let leaves = (1 << depth) - 1;
        println!("leaves={}", leaves);
        let alpha: usize = rand::thread_rng().gen_range(1, leaves);
        println!("alpha={}", alpha);
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        println!("alpha_bits = {:?}", alpha_bits);
        alpha_bits.reverse();
        println!("alpha_bits_rev = {:?}", alpha_bits);
        let alpha_keys: Vec<Block> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        println!("alpha keys = {:?}", alpha_keys);
        let leaves = 1 << depth;
        let v_ = ggm_prime::<F61p>(alpha, &alpha_keys);
        println!("v_ = {:?}", v_);
        println!("leaves = {}", leaves);
        for i in 0..v_.len() {
            println!("i = {}", i);
            if i != alpha {
                assert_eq!(v[i], v_[i]);
            }
        }
    }
    }
}
