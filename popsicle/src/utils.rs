//! Util mostly in support of cuckoo hashing.

use rand::{CryptoRng, Rng};
use scuttlebutt::{AesHash, Block};
use sha2::{Digest, Sha256};

/// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
/// as zero. We need to leave 8 bits free in order to add in the hash index when
/// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
pub fn compress_and_hash_inputs(inputs: &[Vec<u8>], key: Block) -> Vec<Block> {
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
                let mut hasher = Sha256::new(); // XXX can we do better than using SHA-256?
                hasher.update(input);
                let h = hasher.finalize();
                digest[0..16].copy_from_slice(&h[0..16]);
            }
            let block = aes.cr_hash(Block::from(i as u128), Block::from(digest));
            block & mask
        })
        .collect::<Vec<Block>>()
}

#[allow(dead_code)]
/// used in tests
pub fn rand_vec<RNG: CryptoRng + Rng>(n: usize, rng: &mut RNG) -> Vec<u8> {
    (0..n).map(|_| rng.gen()).collect()
}

#[allow(dead_code)]
/// used in tests
pub fn rand_vec_vec<RNG: CryptoRng + Rng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m, rng)).collect()
}

#[allow(dead_code)]
/// used in tests
pub fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64> {
    (0..n).map(|_| rng.gen::<u64>() % modulus).collect()
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
