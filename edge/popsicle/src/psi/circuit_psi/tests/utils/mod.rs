//! Various utility functionalities for tests

#[cfg(test)]
use swanky_block::Block;
#[cfg(test)]
use swanky_block::Block512;

#[cfg(test)]
use std::collections::HashSet;

#[cfg(test)]
use proptest::{collection, strategy::Strategy};

#[cfg(test)]
use rand::RngExt;

#[cfg(test)]
/// Create a proptest strategy that creates sets of elements represented as vectors of bytes.
/// Reminder: sets have unique elements, we ensure this by generating hashsets using proptests
/// and turning them into vecs.
pub fn arbitrary_unique_sets(size: usize, max_value: u128) -> impl Strategy<Value = Vec<Vec<u8>>> {
    collection::hash_set(0..max_value, size).prop_map(|v| {
        v.into_iter()
            .map(|value| value.to_le_bytes().to_vec())
            .collect()
    })
}

#[cfg(test)]
/// Create a proptest strategy that creates payloads represented as u128.
pub fn arbitrary_payloads_u128(size: usize, max_value: u128) -> impl Strategy<Value = Vec<u128>> {
    collection::vec(0..max_value, size)
}

#[cfg(test)]
/// Create a proptest strategy that creates payloads represented as Block512.
pub fn arbitrary_payloads_block125(
    size: usize,
    max_value: u128,
) -> impl Strategy<Value = Vec<Block512>> {
    collection::vec(0..max_value, size).prop_map(|v| {
        v.into_iter()
            .map(|value| {
                let value_bytes = value.to_le_bytes();
                let mut value_block512 = [0u8; 64];
                value_block512[0..16].copy_from_slice(&value_bytes[..16]);
                Block512::from(value_block512)
            })
            .collect()
    })
}

#[cfg(test)]
/// Create a vector of Block, from a vector of vectors of u8
pub fn u8_vec_block(values: &[Vec<u8>], size: usize) -> Vec<Block> {
    values
        .iter()
        .map(|item| {
            let mut res_block = [0_u8; 16];
            res_block[0..size].copy_from_slice(&item[..size]);
            Block::from(res_block)
        })
        .collect()
}

#[cfg(test)]
/// Create a vector of Block512, from a vector of vectors of u8
pub fn u8_vec_block512(values: &[Vec<u8>], size: usize) -> Vec<Block512> {
    values
        .iter()
        .map(|item| {
            let mut res_bytes = [0_u8; 16];
            res_bytes[0..size].copy_from_slice(&item[..size]);
            Block512::from([
                Block::from(res_bytes),
                Block::from(0),
                Block::from(0),
                Block::from(0),
            ])
        })
        .collect()
}

#[cfg(test)]
/// Enumarate ids for testing purposes
pub fn enum_ids(n: usize, starting_position: u64, id_size: usize) -> Vec<Vec<u8>> {
    let vec: Vec<u64> = (starting_position..(n as u64 + starting_position)).collect();
    let mut ids = Vec::with_capacity(n);
    for x in vec.iter().take(n) {
        let v: Vec<u8> = x.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

#[cfg(test)]
use rand::CryptoRng;
#[cfg(test)]
/// Generate a random `Vec` of `n` `u128`, modulo `modulus`.
pub fn rand_u128_vec<RNG: CryptoRng>(n: usize, modulus: u128, rng: &mut RNG) -> Vec<u128> {
    (0..n).map(|_| rng.random::<u128>() % modulus).collect()
}
#[cfg(test)]
/// Generate a random `Vec` of `n` `u128`, modulo `modulus`, as little-endian
/// `Vec`s of bytes.
pub fn rand_u8_vec<RNG: CryptoRng>(n: usize, modulus: u128, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n)
        .map(|_| (rng.random::<u128>() % modulus).to_le_bytes().to_vec())
        .collect()
}

#[cfg(test)]
/// Generate a random `Vec` of `n` _unique_ `u128`, modulo `modulus`, as
/// little-endian `Vec`s of bytes.
pub fn rand_u8_vec_unique<RNG: CryptoRng>(n: usize, modulus: u128, rng: &mut RNG) -> Vec<Vec<u8>> {
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
