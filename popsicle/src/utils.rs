// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesHash, Block, Block512};
use sha2::{Digest, Sha256};
use itertools::Itertools;
use fancy_garbling::Wire;
use std::collections::HashMap;

// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
// as zero. We need to leave 8 bits free in order to add in the hash index when
// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
pub fn compress_and_hash_inputs(inputs: &[Vec<u8>], key: Block) -> Vec<Block> {
    let mut hasher = Sha256::new(); // XXX can we do better than using SHA-256?
    let aes = AesHash::new(key);
    let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00);
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut digest = [0u8; 16];
            if input.len() <= 16 {
                // Map `input` directly to a `Block`.
                digest[0..input.len()].copy_from_slice(input);
            } else {
                // Hash `input` first.
                hasher.input(input);
                let h = hasher.result_reset();
                digest[0..16].copy_from_slice(&h[0..16]);
            }
            let block = aes.cr_hash(Block::from(i as u128), Block::from(digest));
            block & mask
        })
        .collect::<Vec<Block>>()
}

#[allow(dead_code)] // used in tests
pub fn rand_vec<RNG: CryptoRng + Rng>(n: usize, rng: &mut RNG) -> Vec<u8> {
    (0..n).map(|_| rng.gen()).collect()
}

#[allow(dead_code)] // used in tests
pub fn rand_vec_vec<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m, rng)).collect()
}

pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values.into_iter()
          .map(|item|{
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..8{
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
         }).collect()
}

pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64>{
    (0..n).map(|_| rng.gen::<u64>()%modulus).collect()
}

pub fn enum_ids(n: usize, id_size: usize) ->Vec<Vec<u8>>{
    let mut ids = Vec::with_capacity(n);
    for i in 0..n as u64{
        let v:Vec<u8> = i.to_le_bytes().iter().take(id_size).cloned().collect();
        ids.push(v);
    }
    ids
}

pub fn generate_deltas(primes: &[u16]) -> HashMap<u16, Wire> {
    let mut deltas = HashMap::new();
    let mut rng = rand::thread_rng();
    for q in primes{
        deltas.insert(*q, Wire::rand_delta(&mut rng, *q));
    }
    deltas
}


//Assumes payloads are up to 64bit long
pub fn mask_payload_crt<RNG: Rng + CryptoRng>(x: Block512, y: Block512, rng:&mut RNG)
        -> Block512{

    let x_crt = block512_to_crt(x);
    let y_crt = block512_to_crt(y);
    let q = fancy_garbling::util::primes_with_width(64);
    let mut res_crt = Vec::new();
    for i in 0..q.len(){
        res_crt.push((x_crt[i]+y_crt[i]) % q[i]);
    }
    let res = fancy_garbling::util::crt_inv(&res_crt, &q).to_le_bytes();
    let mut block = [0 as u8; 64];
    for i in 0..64{
        if i < res.len(){
            block[i] = res[i];
        }else{
            block[i] = rng.gen::<u8>();
        }
    }
    Block512::from(block)
}

//Assumes payloads are up to 64bit long i.e 8 bytes
fn block512_to_crt(b: Block512) -> Vec<u16>{
    let b_val = b.prefix(8);

    let mut b_128 = [0 as u8; 16];

    // Loop over the 8 bytes of 64b b_val
    for i in 0..8{
        b_128[i] = b_val[i];
    }

    let q = fancy_garbling::util::primes_with_width(64);
    let b_crt = fancy_garbling::util::crt(u128::from_le_bytes(b_128), &q);
    b_crt
}


#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;

    #[test]
    fn test_compress_and_hash_inputs() {
        let mut rng = AesRng::new();
        let key = rng.gen::<Block>();
        let inputs = rand_vec_vec(13, 16, &mut rng);
        let _ = compress_and_hash_inputs(&inputs, key);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use scuttlebutt::AesRng;
    use test::Bencher;

    const NTIMES: usize = 1 << 16;

    #[bench]
    fn bench_compress_and_hash_inputs_small(b: &mut Bencher) {
        let mut rng = AesRng::new();
        let key = rng.gen::<Block>();
        let inputs = rand_vec_vec(NTIMES, 15, &mut rng);
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }

    #[bench]
    fn bench_compress_and_hash_inputs_large(b: &mut Bencher) {
        let mut rng = AesRng::new();
        let key = rng.gen::<Block>();
        let inputs = rand_vec_vec(NTIMES, 32, &mut rng);
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }
}
