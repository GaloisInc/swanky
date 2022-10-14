//! Provides an implementation of the GGM construction.

use crate::svole::wykw::specialization::FiniteFieldSpecialization;
use scuttlebutt::{field::FiniteField, utils::unpack_bits};
use vectoreyes::{
    array_utils::ArrayUnrolledExt, Aes128EncryptOnly, AesBlockCipher, SimdBase, U8x16,
};

#[derive(Default)]
pub(crate) struct GgmTemporaryStorage {
    seeds: Vec<U8x16>,
}

/// Implementation of GGM based on the procedure explained in the write-up
/// (<https://eprint.iacr.org/2020/925.pdf>, Page 14) -- Construct GGM tree with
/// `depth` levels and return the node values (a.k.a seeds). `aes` is used to
/// seed the "PRGs" used internally so we don't need to instantiate new PRGs on
/// each iteration. Instead, we key two instances of AES ahead of time and view
/// them as PRPs, using the seed as input. We then use the [scuttlebutt::AesHash::cr_hash]
/// construction on top of AES.
///
/// `keys_out` **WILL NOT** be `clear()`ed. Results will be appended to it.
///
/// `tmp_storage` allows `ggm` to preserve allocations across invocations.
/// `depth` doesn't count the "root" node.
pub(super) fn ggm<FE: FiniteField, T: From<U8x16>>(
    depth: usize,
    initial_seed: U8x16,
    aes: &(Aes128EncryptOnly, Aes128EncryptOnly),
    results: &mut [FE],
    keys_out: &mut Vec<(T, T)>,
    tmp_storage: &mut GgmTemporaryStorage,
) {
    let seeds = &mut tmp_storage.seeds;
    seeds.resize(1 << (depth + 1), U8x16::ZERO);
    let seeds: &mut [U8x16] = seeds.as_mut_slice();
    seeds[0] = initial_seed;
    // We do a level-order traversal. We could conceivably do a depth-first traversal of the tree,
    // (which would avoid the need for a large intermediate buffer). However, then we wouldn't be
    // able to perform any parallel AES encryptions, which is more important for performance than
    // a little bit less memory usage.
    //
    // The seeds vector contains a level-order traversal of the GGM tree.
    for i in 0..depth {
        // i is the index of the _previous_/source level. We write into level i+1.
        let mut k0 = U8x16::ZERO;
        let mut k1 = U8x16::ZERO;
        let (prev_levels, current_level_and_beyond) = seeds.split_at_mut((1 << (i + 1)) - 1);
        let prev_level = &prev_levels[(1 << i) - 1..(1 << (i + 1)) - 1];
        let current_level = &mut current_level_and_beyond[0..1 << (i + 1)];
        debug_assert_eq!(prev_level.len(), 1 << i, "i={}", i);
        debug_assert_eq!(current_level.len(), 1 << (i + 1));
        debug_assert_eq!(current_level.len() % 2, 0);
        debug_assert_eq!(current_level.len(), 2 * prev_level.len());
        let prev_chunks = prev_level.chunks_exact(Aes128EncryptOnly::BLOCK_COUNT_HINT);
        let prev_remainder = prev_chunks.remainder();
        let current_chunks =
            current_level.chunks_exact_mut(Aes128EncryptOnly::BLOCK_COUNT_HINT * 2);
        // This loop does the same job as:
        // let mut k0 = Default::default();
        // let mut k1 = Default::default();
        // let exp = 1 << i;
        // for j in 0..exp {
        //     let s = seeds[j + exp - 1];
        //     let s0 = aes.0.encrypt(s) ^ s;
        //     let s1 = aes.1.encrypt(s) ^ s;
        //     k0 ^= s0;
        //     k1 ^= s1;
        //     seeds.push(s0);
        //     seeds.push(s1);
        // }
        // keys.push((k0, k1));
        for (current, chunk) in current_chunks.zip(prev_chunks) {
            let chunk: [U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT] = chunk
                .try_into()
                .expect("Chunks ought to be the size we've specified.");
            let s0 = aes.0.encrypt_many(chunk);
            let s1 = aes.1.encrypt_many(chunk);
            let s0 = s0.array_zip(chunk).array_map(
                #[inline(always)]
                |(s, chunk)| s ^ chunk,
            );
            let s1 = s1.array_zip(chunk).array_map(
                #[inline(always)]
                |(s, chunk)| s ^ chunk,
            );
            s0.array_zip(s1).array_enumerate().array_for_each(
                #[inline(always)]
                |(i, (s0, s1))| {
                    current[i * 2] = s0;
                    current[i * 2 + 1] = s1;
                },
            );
            k0 = s0.array_fold(
                k0,
                #[inline(always)]
                |a, b| a ^ b,
            );
            k1 = s1.array_fold(
                k1,
                #[inline(always)]
                |a, b| a ^ b,
            );
        }
        let current_remainder = current_level
            .chunks_exact_mut(Aes128EncryptOnly::BLOCK_COUNT_HINT * 2)
            .into_remainder();
        debug_assert_eq!(current_remainder.len() % 2, 0);
        for (current, s) in current_remainder.chunks_exact_mut(2).zip(prev_remainder) {
            let s0 = aes.0.encrypt(*s) ^ *s;
            let s1 = aes.1.encrypt(*s) ^ *s;
            current[0] = s0;
            current[1] = s1;
            k0 ^= s0;
            k1 ^= s1;
        }
        keys_out.push((k0.into(), k1.into()));
    }
    // TODO: fuse this loop with the previous loop.
    let exp = 1 << depth;
    for (v, seed) in results.iter_mut().zip(seeds[exp - 1..].iter()) {
        *v = FE::from_uniform_bytes(&<[u8; 16]>::from(*seed));
    }
}

/// Implementation of GGM' based on the procedure explained in the
/// write-up(<https://eprint.iacr.org/2020/925.pdf>, Page 14), For more detailed
/// explanation of GGM', please see the Figure 1 of the write-up
/// (<https://eprint.iacr.org/2019/1084.pdf>, Page 7). GGM' is used compute the
/// vector of field elements except a path `b1..bn` where `b1` represents the
/// msb of `alpha`.
pub(super) fn ggm_prime<FE: FiniteField, S: FiniteFieldSpecialization<FE>>(
    alpha: usize,
    keys: &[U8x16],
    aes: &(Aes128EncryptOnly, Aes128EncryptOnly),
    results: &mut [S::SenderPairContents],
) -> FE {
    let depth = keys.len();
    let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), depth);
    // To get MSB as first elt.
    alpha_bits.reverse();
    let leaves = 1 << depth;
    let mut sv: Vec<U8x16> = vec![Default::default(); 2 * leaves - 1]; // to store all seeds up to level depth
    sv[1 + !alpha_bits[0] as usize] = keys[0];
    for i in 2..depth + 1 {
        let exp = 1 << (i - 1) as usize; // number of nodes in the prev. level.
        let exp_idx = 1 << i; // starting insertion position at the currrent level.
        for j in 0..exp {
            if sv[exp + j - 1] != Default::default() {
                let s = sv[exp + j - 1];
                let s0 = aes.0.encrypt(s) ^ s;
                let s1 = aes.1.encrypt(s) ^ s;
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
        let s_alpha = (0..exp).fold(Default::default(), |sum: U8x16, j| {
            sum ^ sv[exp_idx + 2 * j + ai_comp as usize - 1]
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
    use super::*;
    use crate::svole::wykw::specialization::{FiniteFieldSpecialization, NoSpecialization};
    use proptest::prelude::*;
    use rand::Rng;
    use scuttlebutt::{
        field::{F128b, F40b, F61p, FiniteField, F2},
        ring::FiniteRing,
        utils::unpack_bits,
    };

    #[test]
    fn test_bv_to_num() {
        let x = rand::random::<usize>();
        let bv = unpack_bits(&x.to_le_bytes(), 64);
        assert_eq!(bv_to_num(&bv), x);
    }

    fn test_ggm_<FE: FiniteField, S: FiniteFieldSpecialization<FE>>(
        depth: usize,
        seed: [u8; 16],
        seed0: [u8; 16],
        seed1: [u8; 16],
    ) -> Result<(), TestCaseError> {
        let seed = U8x16::from(seed);
        let seed0 = U8x16::from(seed0);
        let seed1 = U8x16::from(seed1);
        let aes0 = Aes128EncryptOnly::new_with_key(seed0);
        let aes1 = Aes128EncryptOnly::new_with_key(seed1);
        let ggm_seeds = (aes0, aes1);
        let exp = 1 << depth;
        let mut vs: Vec<FE> = vec![FE::ZERO; exp];
        let mut keys = Vec::new();
        ggm(
            depth,
            seed,
            &ggm_seeds.clone(),
            &mut vs,
            &mut keys,
            &mut GgmTemporaryStorage::default(),
        );
        let leaves = (1 << depth) - 1;
        let alpha: usize = rand::thread_rng().gen_range(1..leaves);
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        alpha_bits.reverse();
        let alpha_keys: Vec<U8x16> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        let mut vs_ = vec![S::new_sender_pair(FE::PrimeField::ZERO, FE::ZERO); exp];
        let _ = ggm_prime::<FE, S>(alpha, &alpha_keys, &ggm_seeds, &mut vs_);
        for i in 0..vs_.len() {
            if i != alpha {
                prop_assert_eq!(vs[i], S::extract_sender_pair(vs_[i]).1);
            }
        }
        Ok(())
    }
    macro_rules! test_ggm {
        ($(($name:ident, $field:ty, $specialization:ty),)*) => {
            $(proptest! {
                #[test]
                fn $name(
                    // Runs for a while if the range is over 20.
                    // depth has to be atleast 2.
                    depth in 2..14_usize,
                    seed in any::<[u8;16]>(),
                    seed0 in any::<[u8; 16]>(),
                    seed1 in any::<[u8; 16]>(),
                ) {
                    test_ggm_::<$field, $specialization>(depth, seed, seed0, seed1)?;
                }
            })*
        };
    }
    test_ggm!(
        (f61p, F61p, NoSpecialization),
        (f2, F2, NoSpecialization),
        (f128b, F128b, NoSpecialization),
        (f40b, F40b, NoSpecialization),
    );
}
