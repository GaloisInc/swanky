// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{field::FiniteField, utils::unpack_bits, AesRng, Block};

/// Returns dot product of two vectors.
pub fn dot_product<'a, FE: FiniteField, A: Iterator<Item = &'a FE>, B: Iterator<Item = &'a FE>>(
    x: A,
    y: B,
) -> FE {
    x.zip(y).map(|(u, v)| *u * *v).sum()
}

/// Returns point-wise addition of two vectors.
pub fn point_wise_addition<
    'a,
    FE: FiniteField,
    A: Iterator<Item = &'a FE>,
    B: Iterator<Item = &'a FE>,
>(
    x: A,
    y: B,
) -> Vec<FE> {
    x.zip(y).map(|(u, v)| *u + *v).collect()
}

/// Scalar multiplication
pub fn scalar_multiplication<FE: FiniteField>(x: FE, v: &[FE]) -> Vec<FE> {
    v.iter().map(|&y| x * y).collect()
}

/// Construct GGM tree with `h` levels and return the node values (a.k.a seeds).
/// Although, the last level seeds to be of type `FE`, we keep them in the form
/// of `Block` type as we need to call do OT calls on them.
pub fn ggm<FE: FiniteField, RNG: CryptoRng + RngCore>(
    depth: usize,
    rng: &mut RNG,
) -> (Vec<FE>, Vec<(Block, Block)>) {
    let mut seeds = Vec::with_capacity((0..depth).fold(0, |acc, i| acc + 2 * (1 << i)));
    let mut keys: Vec<(Block, Block)> = Vec::with_capacity(depth);
    let seed = rng.gen::<Block>();
    seeds.push(seed);
    for i in 0..depth {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            let s = seeds[j + exp - 1];
            let mut rng = AesRng::from_seed(s); // XXX expensive!
            let (s0, s1) = rng.gen::<(Block, Block)>();
            k0 ^= s0;
            k1 ^= s1;
            seeds.push(s0);
            seeds.push(s1);
        }
        keys.push((k0, k1));
    }
    let exp = 1 << depth;
    let vs = (0..exp)
        .map(|j| FE::from_uniform_bytes(&<[u8; 16]>::from(seeds[exp + j - 1])))
        .collect();
    (vs, keys)
}

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
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 14);
            let (v, keys): (Vec<Gf128>, _) = ggm(depth, &mut rand::thread_rng());
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
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 14);
            let (v, keys): (Vec<F2>, _) = ggm(depth, &mut rand::thread_rng());
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
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 10);
            //let depth = 2;
            let (v, keys): (Vec<Fp>, _) = ggm(depth, &mut rand::thread_rng());
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
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 14);
            let (v, keys): (Vec<F61p>, _) = ggm(depth, &mut rand::thread_rng());
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
