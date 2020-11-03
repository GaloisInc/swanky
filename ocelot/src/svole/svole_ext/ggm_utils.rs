// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use scuttlebutt::{field::FiniteField, utils::unpack_bits, Aes128, Block};

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

/// Construct GGM tree with `depth` levels and return the node values (a.k.a
/// seeds). `aes_seeds` are used to seed the "PRGs" used internally so we don't
/// need to instantiate new PRGs on each iteration. Instead, we key two
/// instances of AES ahead of time and view them as PRPs, using the seed as
/// input.
pub fn ggm<FE: FiniteField>(
    depth: usize,
    initial_seed: Block,
    aes_seeds: (Block, Block),
) -> (Vec<FE>, Vec<(Block, Block)>) {
    let mut seeds = Vec::with_capacity((0..depth).fold(0, |acc, i| acc + 2 * (1 << i)));
    let mut keys: Vec<(Block, Block)> = Vec::with_capacity(depth);
    let aes0 = Aes128::new(aes_seeds.0);
    let aes1 = Aes128::new(aes_seeds.1);
    seeds.push(initial_seed);
    for i in 0..depth {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            let s = seeds[j + exp - 1];
            let s0 = aes0.encrypt(s);
            let s1 = aes1.encrypt(s);
            // let mut rng = AesRng::from_seed(s); // XXX expensive!
            // let (s0, s1) = rng.gen::<(Block, Block)>();
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

/// GGM prime is used compute the vector of field elements except a path b1..bn
/// where b1 represents msb of alpha.
pub fn ggm_prime<FE: FiniteField>(
    alpha: usize,
    keys: &[Block],
    aes_seeds: (Block, Block),
) -> Vec<FE> {
    let aes0 = Aes128::new(aes_seeds.0);
    let aes1 = Aes128::new(aes_seeds.1);
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
                let s0 = aes0.encrypt(s);
                let s1 = aes1.encrypt(s);
                // let mut rng = AesRng::from_seed(s);
                // let (s0, s1) = rng.gen::<(Block, Block)>();
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
    use super::{bv_to_num, ggm, ggm_prime};
    use rand::Rng;
    use scuttlebutt::field::{F61p, FiniteField, Fp, Gf128, F2};
    use scuttlebutt::utils::unpack_bits;
    use scuttlebutt::Block;

    #[test]
    fn test_bv_to_num() {
        let x = rand::random::<usize>();
        let bv = unpack_bits(&x.to_le_bytes(), 64);
        assert_eq!(bv_to_num(&bv), x);
    }

    fn _test_ggm<FE: FiniteField>() {
        for _ in 0..10 {
            // Runs for a while if the range is over 20.
            // depth has to be atleast 2.
            let depth = rand::thread_rng().gen_range(2, 14);
            let seed = rand::thread_rng().gen();
            let seed0 = rand::thread_rng().gen();
            let seed1 = rand::thread_rng().gen();
            let (v, keys): (Vec<FE>, _) = ggm(depth, seed, (seed0, seed1));
            let leaves = (1 << depth) - 1;
            let alpha: usize = rand::thread_rng().gen_range(1, leaves);
            let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
            alpha_bits.reverse();
            let alpha_keys: Vec<Block> = alpha_bits
                .iter()
                .zip(keys.iter())
                .map(|(b, k)| if !*b { k.1 } else { k.0 })
                .collect();
            let v_ = ggm_prime::<FE>(alpha, &alpha_keys, (seed0, seed1));
            for i in 0..v_.len() {
                if i != alpha {
                    assert_eq!(v[i], v_[i]);
                }
            }
        }
    }

    #[test]
    fn test_ggm() {
        _test_ggm::<Fp>();
        _test_ggm::<F61p>();
        _test_ggm::<F2>();
        _test_ggm::<Gf128>();
    }
}
