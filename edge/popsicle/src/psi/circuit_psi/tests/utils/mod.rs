//! Various utility functionalities for tests

use rand::{CryptoRng, RngExt};
use std::collections::HashSet;
use swanky_block::Block;
use vectoreyes::U8x16;

/// Create a vector of Block, from a vector of vectors of u8
pub(crate) fn u8_vec_block(values: &[Vec<u8>], size: usize) -> Vec<Block> {
    values
        .iter()
        .map(|item| {
            let mut res_block = [0_u8; 16];
            res_block[0..size].copy_from_slice(&item[..size]);
            U8x16::from(res_block)
        })
        .collect()
}

/// Enumarate ids for testing purposes
pub(crate) fn enum_ids(n: usize, starting_position: u64, id_size: usize) -> Vec<Vec<u8>> {
    let vec: Vec<u64> = (starting_position..(n as u64 + starting_position)).collect();
    let mut ids = Vec::with_capacity(n);
    for x in vec.iter().take(n) {
        let v: Vec<u8> = x.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

/// Generate a random `Vec` of `n` `u128`, modulo `modulus`.
pub(crate) fn rand_u128_vec<RNG: CryptoRng>(n: usize, modulus: u128, rng: &mut RNG) -> Vec<u128> {
    (0..n).map(|_| rng.random::<u128>() % modulus).collect()
}

/// Generate a random `Vec` of `n` `u128`, modulo `modulus`, as little-endian
/// `Vec`s of bytes.
pub(crate) fn rand_u8_vec<RNG: CryptoRng>(n: usize, modulus: u128, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n)
        .map(|_| (rng.random::<u128>() % modulus).to_le_bytes().to_vec())
        .collect()
}

/// Generate a random `Vec` of `n` _unique_ `u128`, modulo `modulus`, as
/// little-endian `Vec`s of bytes.
pub(crate) fn rand_u8_vec_unique<RNG: CryptoRng>(
    n: usize,
    modulus: u128,
    rng: &mut RNG,
) -> Vec<Vec<u8>> {
    let mut unique = HashSet::new();
    for _ in 0..n {
        loop {
            let el = rng.random::<u128>() % modulus;
            if !unique.contains(&el) {
                unique.insert(el);
                break;
            }
        }
    }
    unique
        .into_iter()
        .map(|value| value.to_le_bytes().to_vec())
        .collect()
}
