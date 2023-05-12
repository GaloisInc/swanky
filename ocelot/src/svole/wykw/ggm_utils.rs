//! Provides an implementation of the GGM construction.

use scuttlebutt::field::{FiniteField, IsSubFieldOf};
use vectoreyes::{
    array_utils::ArrayUnrolledExt, Aes128EncryptOnly, AesBlockCipher, SimdBase, U8x16,
};

/// How many `U8x16`s must fit in the `tmp_storage` slice?
pub const fn ggm_temporary_storage_size(depth: usize) -> usize {
    1 << (depth + 1)
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
/// it should be able to store `depth` items.
///
/// `tmp_storage` allows `ggm` to preserve allocations across invocations. It should be a slice
/// of size `ggm_temporary_storage_size(depth)`. Its contents should be ignored.
/// `depth` doesn't count the "root" node.
pub fn ggm<FE: FiniteField, T: From<U8x16>, Dst: Extend<(T, T)>>(
    depth: usize,
    initial_seed: U8x16,
    aes: &(Aes128EncryptOnly, Aes128EncryptOnly),
    results: &mut [FE],
    keys_out: &mut Dst,
    tmp_storage: &mut [U8x16],
) {
    let seeds = tmp_storage;
    assert_eq!(seeds.len(), ggm_temporary_storage_size(depth));
    seeds[0] = initial_seed;
    // We do a level-order traversal. We could conceivably do a depth-first traversal of the tree,
    // (which would avoid the need for a large intermediate buffer). However, then we wouldn't be
    // able to perform any parallel AES encryptions, which is more important for performance than
    // a little bit less memory usage.
    //
    // The seeds vector contains a level-order traversal of the GGM tree.
    keys_out.extend((0..depth).map(|i| {
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
        (k0.into(), k1.into())
    }));
    // TODO: fuse this loop with the previous loop.
    let exp = 1 << depth;
    for (v, seed) in results.iter_mut().zip(seeds[exp - 1..].iter()) {
        *v = FE::from_uniform_bytes(&<[u8; 16]>::from(*seed));
    }
}

/// How many `U8x16`s must fit in the `tmp_storage` slice?
pub fn ggm_prime_temporary_storage_size(depth: usize) -> usize {
    let leaves = 1 << depth;
    2 * leaves - 2
}

/// Implementation of GGM' based on the procedure explained in the
/// write-up(<https://eprint.iacr.org/2020/925.pdf>, Page 14), For more detailed
/// explanation of GGM', please see the Figure 1 of the write-up
/// (<https://eprint.iacr.org/2019/1084.pdf>, Page 7). GGM' is used compute the
/// vector of field elements except a path `b1..bn` where `b1` represents the
/// msb of `alpha`.
///
/// `ot_output` are the values that we've received via OT.
///
/// The value at `results[alpha]` is unspecified. (That is, do not depend on its output being a
/// specific value, but it will be properly initialized to avoid Undefined Behavior.)
///
/// This code will leave all the prime field elements of the sender pair untouched.
///
/// `tmp_storage` allows `ggm_prime` to preserve allocations across invocations. It should be a slice
/// of size `ggm_prime_temporary_storage_size(ot_output.len())`. Its contents should be ignored.
///
/// # Preconditions
/// * `results.len()` should be `1 << ot_output.len()`.
/// * `alpha` should be strictly less then `1 << ot_output.len()`
///
/// # Return Value
/// This function will return the sum of the `.1` elements in the results array
pub fn ggm_prime<
    VF: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    T: From<(VF, FE)> + Into<(VF, FE)> + Copy,
>(
    alpha: usize,
    ot_output: &[U8x16],
    aes: &(Aes128EncryptOnly, Aes128EncryptOnly),
    results: &mut [T],
    tmp_storage: &mut [U8x16],
) -> FE {
    // TODO: several constant-time MUXes are currently written as if statements. We need a more
    // efficient constant time library compared to subtle.
    let depth = ot_output.len();
    let leaves = 1 << depth;
    assert_eq!(leaves, results.len());
    debug_assert!(alpha < leaves);
    assert!(depth >= 2);
    // sv contains a level-order traversal of the seeds in the seed tree.
    let mut sv = tmp_storage;
    assert_eq!(sv.len(), 2 * leaves - 2);
    // When implemented GGM', we need to be careful to _not_ use alpha as part of the index to any
    // array accesses. It's a secret value, and so using it as part of an array access can lead to
    // timing attacks.
    // We set both keys at the first level to the first key that we recieve. The one of these values
    // will never be used since it corresponds to the path that we've selected with alpha.
    sv[0] = ot_output[0];
    sv[1] = ot_output[0];
    let mut previous_level_reconstruction = ot_output[0];
    for level in 2..=depth {
        let (prev_level, remaining_sv) = sv.split_at_mut(1 << (level - 1));
        sv = remaining_sv;
        let current_level = &mut sv[0..(1 << level)];
        debug_assert!(prev_level.len().is_power_of_two());
        debug_assert_eq!(current_level.len(), prev_level.len() * 2);
        let which_parent_node_is_unknown = alpha >> (depth - level + 1);
        let which_parent_node_was_reconstructed = which_parent_node_is_unknown ^ 1;
        // Apply our PRF (lambda s: aes.encrypt(s) ^ s) to the previous level to generate the new
        // level.
        let mut level_xor = ot_output[level - 1];
        let mut prev_level = prev_level.chunks_exact(Aes128EncryptOnly::BLOCK_COUNT_HINT);
        let mut i = 0;
        for parents in prev_level.by_ref() {
            let parents = <&[U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT]>::try_from(parents)
                .expect("The chunk size matches");
            let parents = parents.array_enumerate().array_map(
                #[inline(always)]
                |(j, parent)| {
                    // TODO: constant time
                    if i + j == which_parent_node_was_reconstructed {
                        previous_level_reconstruction
                    } else {
                        parent
                    }
                },
            );
            let keys = [&aes.0, &aes.1];
            // Array of [which key][which parent index] => PRF output
            let current_level_entries = keys.array_map(
                #[inline(always)]
                |key| {
                    let encryptions = key.encrypt_many(parents);
                    // Uncommenting the below gives a 5% reduction in nanoseconds per VOLE.
                    // This code block is currently specialized to BLOCK_COUNT_HINT==4. If you want
                    // to uncomment this block for realsies, then you should modify the surrounding
                    // code to force it to encrypt exactly 4 blocks at a time. (We do that in other
                    // places in the code, anyway.)
                    /*let encryptions: [U8x16; 4] = unsafe {
                    let mut encryptions: [std::arch::x86_64::__m128i; 4] =
                        bytemuck::cast(encryptions);
                    std::arch::asm!(
                        "/* {} {} {} {} */
",
                            inout(xmm_reg) encryptions[0],
                            inout(xmm_reg) encryptions[1],
                            inout(xmm_reg) encryptions[2],
                            inout(xmm_reg) encryptions[3],
                            options(pure, nomem, nostack, preserves_flags),
                        );
                        bytemuck::cast(encryptions)
                    };*/
                    encryptions.array_zip(parents).array_enumerate().array_map(
                        #[inline(always)]
                        |(j, (key, parent))| {
                            let new_node = key ^ parent;
                            // TODO: constant time
                            if i + j == which_parent_node_is_unknown {
                                U8x16::ZERO
                            } else {
                                new_node
                            }
                        },
                    )
                },
            );
            // We transpose the array.
            // Array of [which parent index][which key] => PRF output
            let current_level_entries =
                <[[U8x16; 2]; Aes128EncryptOnly::BLOCK_COUNT_HINT]>::array_generate(
                    #[inline(always)]
                    |j| [current_level_entries[0][j], current_level_entries[1][j]],
                );
            current_level_entries.array_enumerate().array_for_each(
                #[inline(always)]
                |(j, [s0, s1])| {
                    // TODO: constant time
                    level_xor ^= if (alpha >> (depth - level)) & 1 == 1 {
                        s0
                    } else {
                        s1
                    };
                    current_level[(i + j) * 2] = s0;
                    current_level[(i + j) * 2 + 1] = s1;
                },
            );
            // TODO: write current_level_entries
            i += Aes128EncryptOnly::BLOCK_COUNT_HINT;
        }
        for (i, (parent, current)) in prev_level
            .remainder()
            .iter()
            .copied()
            .zip(current_level.chunks_exact_mut(2))
            .enumerate()
        {
            // TODO: constant time
            let parent = if i == which_parent_node_was_reconstructed {
                previous_level_reconstruction
            } else {
                parent
            };
            let s0 = aes.0.encrypt(parent) ^ parent;
            let s1 = aes.1.encrypt(parent) ^ parent;
            // TODO: constant time
            let s0 = if i == which_parent_node_is_unknown {
                U8x16::ZERO
            } else {
                s0
            };
            let s1 = if i == which_parent_node_is_unknown {
                U8x16::ZERO
            } else {
                s1
            };
            current[0] = s0;
            current[1] = s1;
            // TODO: constant time
            level_xor ^= if (alpha >> (depth - level)) & 1 == 1 {
                s0
            } else {
                s1
            };
        }
        previous_level_reconstruction = level_xor;
    }
    debug_assert_eq!(sv.len(), leaves);
    let mut w_sum = FE::ZERO;
    for (i, (dst, src)) in results.iter_mut().zip(sv.iter()).enumerate() {
        let (u, _w) = (*dst).into();
        // TODO: constant-time
        let w = FE::from_uniform_bytes(bytemuck::cast_ref(if i ^ 1 == alpha {
            &previous_level_reconstruction
        } else {
            src
        }));
        // TODO: constant-time
        if i != alpha {
            w_sum += w;
        }
        *dst = (u, w).into();
    }
    w_sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use scuttlebutt::{
        field::{F128b, F61p, F63b, FiniteField, F2},
        utils::unpack_bits,
    };

    fn test_ggm_<VF: FiniteField + IsSubFieldOf<FE>, FE: FiniteField>(
        depth: usize,
        seed: [u8; 16],
        seed0: [u8; 16],
        seed1: [u8; 16],
        alpha: usize,
    ) -> Result<(), TestCaseError> {
        assert!(alpha < (1 << depth));
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
            &mut vec![U8x16::ZERO; ggm_temporary_storage_size(depth)],
        );
        let mut alpha_bits = unpack_bits(&alpha.to_le_bytes(), keys.len());
        alpha_bits.reverse();
        let alpha_keys: Vec<U8x16> = alpha_bits
            .iter()
            .zip(keys.iter())
            .map(|(b, k)| if !*b { k.1 } else { k.0 })
            .collect();
        let mut vs_ = vec![(VF::ZERO, FE::ZERO); exp];
        let sum = ggm_prime::<VF, FE, (VF, FE)>(
            alpha,
            &alpha_keys,
            &ggm_seeds,
            &mut vs_,
            &mut vec![U8x16::ZERO; ggm_prime_temporary_storage_size(alpha_keys.len())],
        );
        for i in 0..vs_.len() {
            if i != alpha {
                prop_assert_eq!(vs[i], vs_[i].1);
            }
        }
        prop_assert_eq!(sum, vs_.iter().map(|x| x.1).sum());
        Ok(())
    }
    macro_rules! test_ggm {
        ($(($name:ident, $vf:ty, $field:ty),)*) => {
            $(proptest! {
                #[test]
                fn $name(
                    // Runs for a while if the range is over 20.
                    // depth has to be atleast 2.
                    seed in any::<[u8;16]>(),
                    seed0 in any::<[u8; 16]>(),
                    seed1 in any::<[u8; 16]>(),
                    (depth, alpha) in (2..14_usize)
                        .prop_flat_map(|depth| (Just(depth), 0_usize..(1_usize << depth))),
                ) {
                    test_ggm_::<$vf, $field>(depth, seed, seed0, seed1, alpha)?;
                }
            })*
        };
    }
    test_ggm!(
        (f61p, F61p, F61p),
        (f128b, F2, F128b),
        (f63b, F2, F63b),
        (f63b_full_field, F63b, F63b),
    );
}
