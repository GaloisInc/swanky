// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use num::pow;
use rand::{Rng, SeedableRng};
use scuttlebutt::{field::FiniteField as FF, utils::unpack_bits, AesRng, Block};

/// Constructing GGM tree with `h-1` levels.
fn prg(depth: usize, seed: Block) -> Vec<Block> {
    let h = depth;
    let mut sv = Vec::new();
    sv.push(seed);
    for i in 1..h + 1 {
        let exp = pow(2, i - 1);
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
    let sv = prg(h, seed); // XXX what does `sv` stand for?
    let mut keys: Vec<(Block, Block)> = vec![Default::default(); h];
    for i in 0..h {
        let mut k0 = Default::default();
        let mut k1 = Default::default();
        let exp = 1 << i;
        for j in 0..exp {
            k0 ^= sv[2 + j + exp - 1]; // Even keys
            k1 ^= sv[1 + j + exp - 1]; // Odd keys
        }
        keys[i] = (k0, k1);
    }
    let exp = 1 << h;
    let mut vs = vec![FE::zero(); exp];
    for j in 0..exp {
        vs[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(sv[j + exp - 1]));
    }
    (vs, keys)
}

/// GGM prime is used compute the vector of field elements except one entry at `alpha`.
//TODO: this can be fixed and optimized later.
pub fn ggm_prime<FE: FF>(alpha: usize, keys: &[Block]) -> Vec<FE> {
    let h = keys.len();
    println!("alpha = {}", alpha);
    let mut a = unpack_bits(&alpha.to_le_bytes(), h);
    a.reverse();
    println!("alpha bits = {:?}", a);
    let zero = Block::default();
    let mut sv: Vec<Block> = vec![Default::default(); 1 << h];
    sv.insert(1 + !a[0] as usize, keys[0]);
    for i in 2..h {
        let exp = 2 << (i - 1);
        let mut tmp = a.clone();
        tmp.truncate(i - 1);
        for j in 0..exp - 1 {
            // XXX why to u128? convert to usize directly
            if j == bv_to_u128(&tmp) as usize {
                continue;
            } else {
                let mut rng = AesRng::from_seed(sv[j + exp - 1]);
                let (s0, s1) = rng.gen::<(Block, Block)>();
                sv.insert(2 * j + (1 << i) - 1, s0);
                sv.insert(2 * j + (1 << i), s1);
            }
        }
        let mut tmp = a.clone();
        tmp.truncate(i);
        let a_i_comp = !a[i - 1];
        tmp.push(a_i_comp);
        let a_i_star = bv_to_u128(&tmp);
        let s_alpha = (0..exp - 1)
            .filter(|j| *j != a_i_star as usize)
            .fold(zero, |mut sum, j| {
                sum ^= sv[pow(2, i) + 2 * j + a_i_comp as usize - 1];
                sum
            });
        sv.insert((a_i_star + pow(2, i)) as usize - 2, s_alpha ^ keys[i - 1]);
    }
    let mut tmp = a.clone();
    tmp.truncate(h - 1);
    let exp = pow(2, h - 1) as usize;
    let len = pow(2, h);
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(FE::zero());
    }
    for j in 0..exp {
        if j == bv_to_u128(&tmp) as usize {
            continue;
        } else {
            // PRG G'
            let mut rng = AesRng::from_seed(sv[exp + j - 1]);
            let (fe0, fe1) = (FE::random(&mut rng), FE::random(&mut rng));
            v.insert(2 * j, fe0);
            v.insert(2 * j + 1, fe1);
            v.pop();
            v.pop();
        }
    }
    let a_l = a[h - 1];
    tmp.push(!a_l);
    tmp.reverse();
    let ind = bv_to_u128(&tmp);
    let mut sum = FE::zero();
    if a_l {
        sum = v.iter().step_by(2).map(|u| *u).sum();
    } else {
        sum = v.iter().skip(1).step_by(2).map(|u| *u).sum();
    }
    sum += FE::from_uniform_bytes(&<[u8; 16]>::from(keys[h - 1]));
    v.insert(ind as usize, sum);
    v
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
    use scuttlebutt::field::Gf128;

    #[test]
    fn test_bv_to_u128() {
        let x = rand::random::<u128>();
        let bv = unpack_bits(&x.to_le_bytes(), 128);
        assert_eq!(bv_to_u128(&bv), x);
    }

    #[test]
    fn test_ggm() {
        for _ in 0..10 {
            let x = rand::random::<Block>();
            // Runs for a while if the range is over 20.
            // let depth = rand::thread_rng().gen_range(1, 18);
            let depth = 3;
            let (v, keys) = ggm::<Gf128>(depth, x);
            let alpha = 2;
            // let alpha = rand::thread_rng().gen_range(0, leaves);
            // XXX This seems wrong? Keys should depend on `alpha`
            let alpha_keys: Vec<Block> = keys.iter().skip(1).map(|k| k.0).collect();
            let leaves = 1 << depth;

            let v_ = ggm_prime::<Gf128>(alpha, &alpha_keys);
            for i in 0..leaves {
                if i != alpha {
                    assert_eq!(v[i], v_[i]);
                } else {
                    assert!(v[i] != v_[i]);
                }
            }
        }
    }
}
