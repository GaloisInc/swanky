use scuttlebutt::{AesHash, Block};
use sha2::{Digest, Sha256};

// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
// as zero. We need to leave 8 bits free in order to add in the hash index when
// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
pub fn compress_and_hash_inputs(inputs: &[Vec<u8>], key: Block) -> Vec<Block> {
    let mut hasher = Sha256::new(); // XXX can we do better than using SHA-256?
    let aes = AesHash::new(key);
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut digest = [0u8; 16];
            if input.len() < 16 {
                // Map `input` directly to a `Block`.
                digest[0..input.len()].copy_from_slice(input);
            } else {
                // Hash `input` first.
                hasher.input(input);
                let h = hasher.result_reset();
                digest[0..15].copy_from_slice(&h[0..15]);
            }
            aes.cr_hash(Block::from(i as u128), Block::from(digest))
        })
        .collect::<Vec<Block>>()
}

#[allow(dead_code)] // used in tests
pub fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

#[allow(dead_code)] // used in tests
pub fn rand_vec_vec(n: usize, m: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_and_hash_inputs() {
        let key = rand::random::<Block>();
        let inputs = rand_vec_vec(13, 16);
        let _ = compress_and_hash_inputs(&inputs, key);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use crate::utils;
    use test::Bencher;

    const NTIMES: usize = 1 << 16;

    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    fn rand_vec_vec(n: usize, size: usize) -> Vec<Vec<u8>> {
        (0..n).map(|_| rand_vec(size)).collect()
    }

    #[bench]
    fn bench_compress_and_hash_inputs_small(b: &mut Bencher) {
        let inputs = rand_vec_vec(NTIMES, 15);
        let key = rand::random::<Block>();
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }

    #[bench]
    fn bench_compress_and_hash_inputs_large(b: &mut Bencher) {
        let inputs = rand_vec_vec(NTIMES, 32);
        let key = rand::random::<Block>();
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }

}
