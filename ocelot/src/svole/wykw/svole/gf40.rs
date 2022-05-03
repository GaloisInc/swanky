use crate::svole::wykw::specialization::{FiniteFieldSendSpecialization, Gf40Specialization};
use crate::svole::wykw::svole::{
    lpn_mtx_indices, ReceiverInternal, SenderInternal, SvoleSpecializationRecv,
    SvoleSpecializationSend,
};
use rand::distributions::Uniform;
use scuttlebutt::field::{FiniteField, Gf40, F2};
use scuttlebutt::{AesRng, UniformIntegersUnderBound};
use std::convert::TryInto;

use vectoreyes::array_utils::ArrayUnrolledExt;
use vectoreyes::{
    I32x4, I32x8, SimdBase, SimdBase32, SimdBase4x64, SimdBase8, SimdBaseGatherable, U32x4, U32x8,
    U64x2, U64x4, U8x32,
};

type SenderPair = u64;

impl SvoleSpecializationSend<Gf40> for Gf40Specialization {
    fn svole_send_internal_inner(
        svole: &mut SenderInternal<Gf40, Self>,
        num_saved: usize,
        rows: usize,
        uws: Vec<SenderPair>,
        base_voles: &mut Vec<SenderPair>,
        svoles: &mut Vec<SenderPair>,
    ) {
        if rows == super::LPN_EXTEND_PARAMS.rows {
            // We want to perform a pairwise XOR on the pair. That's equivalent to just
            // XOR-ing the raw u64.
            internal_inner(
                &mut svole.lpn_rng,
                &svole.base_voles,
                base_voles,
                uws,
                num_saved,
                svoles,
            );
        } else {
            let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());
            for (i, (e, c)) in uws
                .into_iter()
                .map(Gf40Specialization::extract_sender_pair)
                .enumerate()
            {
                let indices = lpn_mtx_indices::<Gf40>(&distribution, &mut svole.lpn_rng);
                // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
                let mut x = e;
                let mut z = c;
                x += indices
                    .iter()
                    .map(|(j, a)| {
                        Gf40Specialization::extract_sender_pair(svole.base_voles[*j]).0 * *a
                    })
                    .sum::<F2>();
                z += indices
                    .iter()
                    .map(|(j, a)| {
                        Gf40Specialization::extract_sender_pair(svole.base_voles[*j])
                            .1
                            .multiply_by_prime_subfield(*a)
                    })
                    .sum::<Gf40>();

                if i < num_saved {
                    base_voles.push(Gf40Specialization::new_sender_pair(x, z));
                } else {
                    svoles.push(Gf40Specialization::new_sender_pair(x, z));
                }
            }
        }
    }
}

impl SvoleSpecializationRecv<Gf40> for Gf40Specialization {
    fn svole_recv_internal_inner(
        svole: &mut ReceiverInternal<Gf40, Self>,
        num_saved: usize,
        rows: usize,
        vs: Vec<Gf40>,
        mut base_voles: &mut Vec<Gf40>,
        mut svoles: &mut Vec<Gf40>,
    ) {
        if rows == super::LPN_EXTEND_PARAMS.rows {
            internal_inner(
                &mut svole.lpn_rng,
                &svole.base_voles,
                &mut base_voles,
                vs,
                num_saved,
                &mut svoles,
            );
        } else {
            let distribution = Uniform::<u32>::from(0..rows.try_into().unwrap());
            for (i, b) in vs.into_iter().enumerate() {
                let indices = lpn_mtx_indices::<Gf40>(&distribution, &mut svole.lpn_rng);
                let mut y = b;

                y += indices
                    .iter()
                    .map(|(j, a)| svole.base_voles[*j].multiply_by_prime_subfield(*a))
                    .sum::<Gf40>();

                if i < num_saved {
                    base_voles.push(y);
                } else {
                    svoles.push(y);
                }
            }
        }
    }
}

#[inline(always)]
fn visit_permutations(
    the_eights: [U32x8; 2],
    // This is the direct output of `sample_20`. So it has values at the even indexed positions.
    the_remaining: U32x8,
    mut check_equality: impl FnMut(U32x8, U32x8),
) {
    // Swap the high and low lanes.
    let swapped_eights = the_eights.array_map(
        #[inline(always)]
        |eight| U32x8::from(U64x4::from(eight).shuffle::<1, 0, 3, 2>()),
    );
    // First compare between all pairs in each 128-bit lane.
    #[inline(always)]
    fn check_equality_permutation<
        F: FnMut(U32x8, U32x8),
        const I3: usize,
        const I2: usize,
        const I1: usize,
        const I0: usize,
    >(
        original: [U32x8; 2],
        arr: [U32x8; 2],
        check_equality: &mut F,
    ) {
        let shuffled = arr.array_map(
            #[inline(always)]
            |eight| eight.shuffle::<I3, I2, I1, I0>(),
        );
        shuffled.array_zip(original).array_for_each(
            #[inline(always)]
            |(a, b)| check_equality(a, b),
        );
    }
    check_equality_permutation::<_, 0, 1, 2, 3>(the_eights, the_eights, &mut check_equality);
    check_equality_permutation::<_, 1, 0, 3, 2>(the_eights, the_eights, &mut check_equality);
    check_equality_permutation::<_, 2, 3, 0, 1>(the_eights, the_eights, &mut check_equality);
    // Now we work with the swapped eights.
    check_equality_permutation::<_, 3, 2, 1, 0>(the_eights, swapped_eights, &mut check_equality);
    check_equality_permutation::<_, 0, 1, 2, 3>(the_eights, swapped_eights, &mut check_equality);
    check_equality_permutation::<_, 1, 0, 3, 2>(the_eights, swapped_eights, &mut check_equality);
    check_equality_permutation::<_, 2, 3, 0, 1>(the_eights, swapped_eights, &mut check_equality);
    // Now we need to check the two remaining values in the lower half of
    // last_two. We do that with a dirty trick! The lower half of last_two
    // is the lower 64-bits of last_two. As a result, if we treat last_two
    // as a vector of 64-bit numbers, and perform a 64-bit broadcast
    // operation, then we can check each of the two remaining values against
    // half of the combined vector.
    // First we extract the relevant values from "the_remaining"
    let the_remaining: [U32x4; 2] = the_remaining.into();
    let the_remaining = the_remaining.array_map(
        #[inline(always)]
        |remaining| remaining.shuffle::<2, 0, 2, 0>(),
    );
    let broadcasted_last_two = the_remaining.array_map(
        #[inline(always)]
        |remaining| U32x8::from(U64x4::broadcast_lo(U64x2::from(remaining))),
    );
    check_equality_permutation::<_, 3, 2, 1, 0>(
        the_eights,
        broadcasted_last_two,
        &mut check_equality,
    );
    check_equality_permutation::<_, 2, 3, 0, 1>(
        the_eights,
        broadcasted_last_two,
        &mut check_equality,
    );
    // Finally, we check that last two values against each other.
    check_equality_permutation::<_, 0, 1, 0, 1>(
        broadcasted_last_two,
        broadcasted_last_two,
        &mut check_equality,
    );
}

// Since we're operating on GF(2^40), the associated prime field has a modulus of 2. As a result,
// the prime field entry that's associated with the matrix entry is always 1.
fn matrix_entries(rng: &mut AesRng, dist: &UniformIntegersUnderBound) -> [U32x8; 3] {
    loop {
        let raw = dist.sample_20(rng);
        let mut acu = 0_u32;
        visit_permutations([raw[0], raw[1]], raw[2], |a, b| {
            acu |= U8x32::from(a.cmp_eq(b)).most_significant_bits();
        });
        if acu == 0 {
            break raw;
        }
    }
}

/// A type which is `#[repr(transparent)]` for `u64`.
unsafe trait TransparentU64: Clone + Copy + 'static {
    fn from_u64(x: u64) -> Self;
    fn to_u64(&self) -> u64;
}
unsafe impl TransparentU64 for u64 {
    #[inline(always)]
    fn from_u64(x: u64) -> Self {
        x
    }
    #[inline(always)]
    fn to_u64(&self) -> u64 {
        *self
    }
}
// We assume the upper bits of Gf40 are zero. That invariant needs to be preserved.
unsafe impl TransparentU64 for Gf40 {
    #[inline(always)]
    fn from_u64(x: u64) -> Self {
        Gf40::from_lower_40(x)
    }
    #[inline(always)]
    fn to_u64(&self) -> u64 {
        self.extract_raw()
    }
}

fn internal_lpn<T: TransparentU64>(
    rng: &mut AesRng,
    dist: &UniformIntegersUnderBound,
    src_base_voles: &Vec<T>,
    uws: &[T],
    dst: &mut Vec<T>,
) {
    assert_eq!(dist.bound() as usize, src_base_voles.len());
    let chunks = uws.chunks_exact(2);
    let remainder = chunks.remainder();
    for pair in chunks {
        let pair = [pair[0], pair[1]];
        // The associated prime field element of the matrix index is always 1, so we ignore it.
        let entries = matrix_entries(rng, dist);
        let src_base_voles = unsafe {
            // SAFETY: TransparentU64 means that T is represented as a u64.
            std::slice::from_raw_parts(src_base_voles.as_ptr() as *const u64, src_base_voles.len())
        };
        let full_entries = [entries[0], entries[1]].array_map(
            #[inline(always)]
            |entries| {
                // Converting to I32 doesn't change anything given the LWE rows bound. We can't gather
                // with a U32 index.
                let entries = I32x8::from(entries);
                let parts: [I32x4; 2] = entries.into();
                parts.array_map(
                    #[inline(always)]
                    |part| unsafe {
                        // SAFETY: each value in part should be under dist.bound() which we've asserted
                        // is equal to the number of base VOLEs
                        U64x4::gather(src_base_voles.as_ptr(), part)
                    },
                )
            },
        );
        // The first two values are the LPN matrix entries for the first half, and the remaining
        // values correspond to the second half.
        let remaining_two = {
            let last_entry: U32x8 = entries[2];
            let important_indices = <[U32x4; 2]>::from(U32x8::from(
                U64x4::from(last_entry.shuffle::<2, 0, 2, 0>()).shuffle::<3, 1, 2, 0>(),
            ))[0];
            debug_assert_eq!(
                important_indices.as_array(),
                [
                    entries[2].extract::<0>(),
                    entries[2].extract::<2>(),
                    entries[2].extract::<4>(),
                    entries[2].extract::<6>(),
                ]
            );
            // Converting to I32 doesn't change anything given the LWE rows bound. We can't gather
            // with a U32 index.
            let important_indices = I32x4::from(important_indices);
            <[U64x2; 2]>::from(unsafe {
                // SAFETY: each value in part should be under dist.bound() which we've asserted
                // is equal to the number of base VOLEs
                U64x4::gather(src_base_voles.as_ptr(), important_indices)
            })
        };
        let groups = full_entries.array_zip(remaining_two);
        let groups = groups
            .array_map(
                #[inline(always)]
                |([four_lpn_entries0, four_lpn_entries1], two_lpn_entries)| {
                    (four_lpn_entries0 ^ four_lpn_entries1, two_lpn_entries)
                },
            )
            .array_map(
                #[inline(always)]
                |(a, b)| {
                    let [x, y] = <[U64x2; 2]>::from(a);
                    (x, y, b)
                },
            )
            .array_map(
                #[inline(always)]
                |(a, b, c)| (a ^ b, c),
            )
            .array_map(
                #[inline(always)]
                |(a, b)| a ^ b,
            )
            .array_map(
                #[inline(always)]
                |a| a.extract::<0>() ^ a.extract::<1>(),
            );
        dst.push(T::from_u64(groups[0] ^ pair[0].to_u64()));
        dst.push(T::from_u64(groups[1] ^ pair[1].to_u64()));
    }
    for t in remainder {
        // Just do them one at-a-time.
        let entries = matrix_entries(rng, dist);
        let indices = [
            entries[0].extract::<0>(),
            entries[0].extract::<1>(),
            entries[0].extract::<2>(),
            entries[0].extract::<3>(),
            entries[0].extract::<4>(),
            entries[0].extract::<5>(),
            entries[0].extract::<6>(),
            entries[0].extract::<7>(),
            entries[2].extract::<0>(),
            entries[2].extract::<2>(),
        ];
        let mut value = t.to_u64();
        for j in indices.iter() {
            value ^= src_base_voles[(*j) as usize].to_u64();
        }
        dst.push(T::from_u64(value));
    }
}

fn internal_inner<T: TransparentU64>(
    rng: &mut AesRng,
    src_base_voles: &Vec<T>,
    dst_base_voles: &mut Vec<T>,
    uws: Vec<T>,
    num_saved: usize,
    svoles: &mut Vec<T>,
) {
    let dist = UniformIntegersUnderBound::new(src_base_voles.len().try_into().unwrap());
    internal_lpn(
        rng,
        &dist,
        src_base_voles,
        &uws[0..num_saved],
        dst_base_voles,
    );
    internal_lpn(rng, &dist, src_base_voles, &uws[num_saved..], svoles);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::Block;

    #[test]
    fn test_visit_permutation_matrix() {
        const BASE0: u32 = 10000;
        const BASE1: u32 = 100;
        const NULL: u32 = 0x666;
        let mut matrices = [[[false; 10]; 10]; 2];
        visit_permutations(
            [BASE0, BASE1]
                .array_map(|base| <[u32; 8]>::array_generate(|i| base + (i as u32)).into()),
            U32x8::from([
                BASE0 + 8,
                NULL,
                BASE0 + 9,
                NULL,
                BASE1 + 8,
                NULL,
                BASE1 + 9,
                NULL,
            ]),
            |a, b| {
                dbg!(a, b);
                let a = a.as_array();
                let b = b.as_array();
                struct Idx {
                    which_matrix: usize,
                    which_entry: usize,
                }
                fn mapper(x: u32) -> Idx {
                    if (BASE0..BASE0 + 10).contains(&x) {
                        Idx {
                            which_matrix: 0,
                            which_entry: (x - BASE0) as usize,
                        }
                    } else {
                        Idx {
                            which_matrix: 1,
                            which_entry: (x - BASE1) as usize,
                        }
                    }
                }
                let a = a.array_map(mapper);
                let b = b.array_map(mapper);
                let which_matrix = a[0].which_matrix;
                for x in a.iter() {
                    assert_eq!(x.which_matrix, which_matrix);
                }
                for x in b.iter() {
                    assert_eq!(x.which_matrix, which_matrix);
                }
                for (x, y) in a.iter().zip(b.iter()) {
                    assert_ne!(y.which_entry, x.which_entry);
                    matrices[x.which_matrix][x.which_entry][y.which_entry] = true;
                    matrices[x.which_matrix][y.which_entry][x.which_entry] = true;
                }
            },
        );
        for matrix in matrices.iter() {
            println!("\nMATRIX\n");
            for row in matrix {
                for cell in row {
                    print!("{}", (*cell) as u32);
                }
                println!("");
            }
        }
        for matrix in matrices.iter() {
            for (i, row) in matrix.iter().enumerate() {
                for (j, cell) in row.iter().enumerate() {
                    assert_eq!(*cell, i != j);
                }
            }
        }
    }

    #[test]
    fn matrix_entries_test() {
        let mut rng = AesRng::from_seed(Block::default());
        let dist = UniformIntegersUnderBound::new(
            super::super::LPN_EXTEND_PARAMS.rows.try_into().unwrap(),
        );
        matrix_entries(&mut rng, &dist);
    }
}
