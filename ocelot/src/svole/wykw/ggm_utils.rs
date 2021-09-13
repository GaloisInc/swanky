// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Provides an implementation of the GGM construction.

use crate::svole::wykw::specialization::FiniteFieldSendSpecialization;
use scuttlebutt::{field::FiniteField, utils::unpack_bits, Aes128, Block};

/// Implementation of GGM based on the procedure explained in the write-up
/// (<https://eprint.iacr.org/2020/925.pdf>, Page 14) -- Construct GGM tree with
/// `depth` levels and return the node values (a.k.a seeds). `aes` is used to
/// seed the "PRGs" used internally so we don't need to instantiate new PRGs on
/// each iteration. Instead, we key two instances of AES ahead of time and view
/// them as PRPs, using the seed as input.
pub fn ggm<FE: FiniteField>(
    depth: usize,
    initial_seed: Block,
    aes: &(Aes128, Aes128),
    results: &mut [FE],
) -> Vec<(Block, Block)> {
    let mut seeds = Vec::with_capacity((0..depth).fold(0, |acc, i| acc + 2 * (1 << i)));
    let mut keys: Vec<(Block, Block)> = Vec::with_capacity(depth);
    seeds.push(initial_seed);
    for i in 0..depth {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            let s = seeds[j + exp - 1];
            let s0 = aes.0.encrypt(s);
            let s1 = aes.1.encrypt(s);
            k0 ^= s0;
            k1 ^= s1;
            seeds.push(s0);
            seeds.push(s1);
        }
        keys.push((k0, k1));
    }
    let exp = 1 << depth;
    for (i, v) in results.iter_mut().enumerate() {
        *v = FE::from_uniform_bytes(&<[u8; 16]>::from(seeds[exp + i - 1]));
    }
    keys
}

/// Implementation of GGM' based on the procedure explained in the
/// write-up(<https://eprint.iacr.org/2020/925.pdf>, Page 14), For more detailed
/// explanation of GGM', please see the Figure 1 of the write-up
/// (<https://eprint.iacr.org/2019/1084.pdf>, Page 7). GGM' is used compute the
/// vector of field elements except a path `b1..bn` where `b1` represents the
/// msb of `alpha`.
pub(super) fn ggm_prime<FE: FiniteField, S: FiniteFieldSendSpecialization<FE>>(
    alpha: usize,
    keys: &[Block],
    aes: &(Aes128, Aes128),
    results: &mut [S::SenderPairContents],
) -> FE {
    let depth = keys.len();
    let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), depth);
    // To get MSB as first elt.
    alpha_bits.reverse();
    let leaves = 1 << depth;
    let mut sv: Vec<Block> = vec![Default::default(); 2 * leaves - 1]; // to store all seeds up to level depth
    sv[1 + !alpha_bits[0] as usize] = keys[0];
    for i in 2..depth + 1 {
        let exp = 1 << (i - 1) as usize; // number of nodes in the prev. level.
        let exp_idx = 1 << i; // starting insertion position at the currrent level.
        for j in 0..exp {
            if sv[exp + j - 1] != Default::default() {
                let s = sv[exp + j - 1];
                let s0 = aes.0.encrypt(s);
                let s1 = aes.1.encrypt(s);
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
        if j != alpha {
            let (u, _w) = S::extract_sender_pair(results[j]);
            results[j] = S::new_sender_pair(
                u,
                FE::from_uniform_bytes(&<[u8; 16]>::from(sv[leaves + j - 1])),
            );
        }
    }
    let sum = (0..leaves)
        .map(|j| S::extract_sender_pair(results[j]).1)
        .sum();

    sum
}

/// Convert bit-vector to a number.
fn bv_to_num(v: &[bool]) -> usize {
    v.iter()
        .enumerate()
        .map(|(i, &v)| (1 << i) * v as usize)
        .sum()
}

#[cfg(test)]
// When this module is included a benchmark, the test functions don't get called.
#[allow(unused_imports, dead_code)]
mod tests {
    use super::{bv_to_num, ggm, ggm_prime};
    use crate::svole::wykw::specialization::{
        FiniteFieldSendSpecialization, Gf40Specialization, NoSpecialization,
    };
    use rand::Rng;
    use scuttlebutt::field::Gf40;
    use scuttlebutt::{
        field::{F61p, FiniteField, Fp, Gf128, F2},
        utils::unpack_bits,
        Aes128, Block,
    };

    #[test]
    fn test_bv_to_num() {
        let x = rand::random::<usize>();
        let bv = unpack_bits(&x.to_le_bytes(), 64);
        assert_eq!(bv_to_num(&bv), x);
    }

    fn test_ggm_<FE: FiniteField, S: FiniteFieldSendSpecialization<FE>>() {
        for _ in 0..10 {
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 14);
            let seed = rand::thread_rng().gen();
            let seed0 = rand::thread_rng().gen();
            let seed1 = rand::thread_rng().gen();
            let aes0 = Aes128::new(seed0);
            let aes1 = Aes128::new(seed1);
            let ggm_seeds = (aes0, aes1);
            let exp = 1 << depth;
            let mut vs: Vec<FE> = vec![FE::ZERO; exp];
            let keys = ggm(depth, seed, &ggm_seeds.clone(), &mut vs);
            let leaves = (1 << depth) - 1;
            let alpha: usize = rand::thread_rng().gen_range(1, leaves);
            let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
            alpha_bits.reverse();
            let alpha_keys: Vec<Block> = alpha_bits
                .iter()
                .zip(keys.iter())
                .map(|(b, k)| if !*b { k.1 } else { k.0 })
                .collect();
            let mut vs_ = vec![S::new_sender_pair(FE::PrimeField::ZERO, FE::ZERO); exp];
            let _ = ggm_prime::<FE, S>(alpha, &alpha_keys, &ggm_seeds, &mut vs_);
            for i in 0..vs_.len() {
                if i != alpha {
                    assert_eq!(vs[i], S::extract_sender_pair(vs_[i]).1);
                }
            }
        }
    }

    #[test]
    fn test_ggm() {
        test_ggm_::<Fp, NoSpecialization>();
        test_ggm_::<F61p, NoSpecialization>();
        test_ggm_::<F2, NoSpecialization>();
        test_ggm_::<Gf128, NoSpecialization>();
        test_ggm_::<Gf40, Gf40Specialization>();
    }
}