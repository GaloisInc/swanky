//! Util mostly in support of cuckoo hashing.

use sha2::{Digest, Sha256};
use swanky_cr_hash::CorrelationRobustHash;
use vectoreyes::U8x16;

#[cfg(test)]
use rand::{CryptoRng, RngExt};

/// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
/// as zero. We need to leave 8 bits free in order to add in the hash index when
/// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
pub fn compress_and_hash_inputs(inputs: &[Vec<u8>], key: U8x16) -> Vec<U8x16> {
    let aes = CorrelationRobustHash::new(key);
    let mask = U8x16::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00);
    inputs
        .iter()
        .map(|input| {
            let mut digest = [0u8; 16];
            // Hash `input` first.
            let mut hasher = Sha256::new(); // XXX can we do better than using SHA-256?
            hasher.update(input);
            let h = hasher.finalize();
            digest[0..16].copy_from_slice(&h[0..16]);
            let block = aes.hash(U8x16::from(digest));
            block & mask
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn rand_vec<RNG: CryptoRng>(n: usize, rng: &mut RNG) -> Vec<u8> {
    (0..n).map(|_| rng.random()).collect()
}

#[cfg(test)]
pub(crate) fn rand_vec_vec<RNG: CryptoRng>(n: usize, m: usize, rng: &mut RNG) -> Vec<Vec<u8>> {
    (0..n).map(|_| rand_vec(m, rng)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_rng::SwankyRng;

    #[test]
    fn test_compress_and_hash_inputs() {
        let mut rng = SwankyRng::new();
        let key = rng.random::<U8x16>();
        let inputs = rand_vec_vec(13, 16, &mut rng);
        let _ = compress_and_hash_inputs(&inputs, key);
    }

    #[test]
    fn inputs_with_zeros_hash_to_different_values() {
        let mut rng = SwankyRng::new();
        let key = rng.random::<U8x16>();
        let inputs_a = rand_vec_vec(8, 8, &mut rng);
        let mut inputs_b = inputs_a.clone();
        inputs_b[0].push(0u8);
        let hash_a = compress_and_hash_inputs(&inputs_a, key);
        let hash_b = compress_and_hash_inputs(&inputs_b, key);
        assert_ne!(hash_a, hash_b);
    }
}
