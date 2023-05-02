use generic_array::typenum::Unsigned;
use scuttlebutt::field::{Degree, DegreeModulo, IsSubFieldOf, SmallBinaryField};
use scuttlebutt::generic_array_length::Arr;
use scuttlebutt::{
    field::{FiniteField, F2},
    AesRng,
};
use std::convert::TryFrom;
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, EvenArrayAdjacentPairs},
    ExtendingCast, I32x4, SimdBase, SimdBase32, SimdBaseGatherable, U16x8, U32x4, U32x8, U64x2,
    U64x4, U8x16,
};

mod lpn_indices;

pub trait FiniteFieldSpecialization<VF: FiniteField + IsSubFieldOf<FE>, FE: FiniteField>:
    'static + Send + Sync + Sized + Clone + Copy
{
    type SenderPairContents: 'static + Sized + Send + Sync + Clone + Copy + std::fmt::Debug;
    fn new_sender_pair(u: VF, w: FE) -> Self::SenderPairContents;
    fn extract_sender_pair(pair: Self::SenderPairContents) -> (VF, FE);
    /// src_base_voles must be 1<<16 long
    fn lpn_sender(
        lpn_rng: &mut AesRng,
        src_base_voles: &[Self::SenderPairContents],
        dst: &mut [Self::SenderPairContents],
    );
    /// src_base_voles must be 1<<16 long
    fn lpn_receiver(lpn_rng: &mut AesRng, src_base_voles: &[FE], dst: &mut [FE]);
    fn spsvole_receiver_consistency_check_compute_vb(
        rng_chi: &mut AesRng,
        y: FE,
        spsvole_result: &[FE],
    ) -> FE {
        spsvole_result
            .iter()
            .map(|v| *v * FE::random(rng_chi))
            .sum::<FE>()
            - y
    }

    // TODO: should this be degree in length? Probably not.
    fn spsvole_sender_compute_va(
        rng_chi: &mut AesRng,
        spsvole_result: &[Self::SenderPairContents],
    ) -> (FE, Arr<VF, DegreeModulo<VF, FE>>) {
        generic_spsvole_sender_compute_va::<VF, FE, Self>(rng_chi, spsvole_result)
    }
}

#[derive(Clone, Copy)]
pub enum NoSpecialization {}
impl<VF: FiniteField + IsSubFieldOf<FE>, FE: FiniteField> FiniteFieldSpecialization<VF, FE>
    for NoSpecialization
{
    type SenderPairContents = (VF, FE);

    #[inline(always)]
    fn new_sender_pair(u: VF, w: FE) -> Self::SenderPairContents {
        (u, w)
    }

    #[inline(always)]
    fn extract_sender_pair(pair: Self::SenderPairContents) -> (VF, FE) {
        pair
    }

    fn lpn_sender(
        lpn_rng: &mut AesRng,
        src_base_voles: &[Self::SenderPairContents],
        uws: &mut [Self::SenderPairContents],
    ) {
        assert_eq!(src_base_voles.len(), 1 << 16);
        for ((e, z), matrix_entries) in uws
            .iter_mut()
            .zip(lpn_indices::matrix_entries::<VF>(lpn_rng))
        {
            // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
            // Then overwrite e with x and c with z
            for (j, a) in matrix_entries {
                let (u, w) = src_base_voles[j as usize];
                *e += u * a;
                *z += a * w;
            }
        }
    }

    fn lpn_receiver(lpn_rng: &mut AesRng, src_base_voles: &[FE], vs: &mut [FE]) {
        assert_eq!(src_base_voles.len(), 1 << 16);
        for (b, matrix_entries) in vs
            .iter_mut()
            .zip(lpn_indices::matrix_entries::<VF>(lpn_rng))
        {
            *b += matrix_entries
                .iter()
                .map(|(j, a)| *a * src_base_voles[*j as usize])
                .sum();
        }
    }
}

// TODO[fullfield]: should this be degree in length? Probably not.
fn generic_spsvole_sender_compute_va<
    VF: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    S: FiniteFieldSpecialization<VF, FE>,
>(
    rng_chi: &mut AesRng,
    spsvole_result: &[S::SenderPairContents],
) -> (FE, Arr<VF, DegreeModulo<VF, FE>>) {
    let mut x_stars: Arr<VF, DegreeModulo<VF, FE>> = Default::default();
    let mut va = FE::ZERO;
    for (u, w) in spsvole_result.iter().copied().map(S::extract_sender_pair) {
        let chi = FE::random(rng_chi);
        va += chi * w;
        // TODO: copee claim doesn't hold up.
        // There will be one, and exactly one, `u` (= `β`) which is
        // non-zero.
        // TODO: fix the side-channel attack here
        if u != VF::ZERO {
            // TODO[fullfield]: what to do here?
            for (x, y) in x_stars.iter_mut().zip(chi.decompose::<VF>().into_iter()) {
                *x += u * y;
            }
        }
    }
    (va, x_stars)
}

#[derive(Clone, Copy)]
pub enum SmallBinaryFieldSpecialization {}
impl<FE: SmallBinaryField> FiniteFieldSpecialization<F2, FE> for SmallBinaryFieldSpecialization
where
    F2: IsSubFieldOf<FE>, // This is required by SmallBinaryField, but rust can't infer that it's true
{
    type SenderPairContents = u64;

    #[inline(always)]
    fn new_sender_pair(u: F2, w: FE) -> u64 {
        ((bool::from(u) as u64) << 63) | FE::peel(w)
    }

    #[inline(always)]
    fn extract_sender_pair(pair: u64) -> (F2, FE) {
        debug_assert_eq!(
            pair & ((u64::MAX >> 1) & (!((1 << FE::NumberOfBitsInBitDecomposition::U64) - 1))),
            0
        );
        (F2::from((pair >> 63) != 0), FE::from_lower_bits(pair))
    }

    fn lpn_sender(
        lpn_rng: &mut AesRng,
        src_base_voles: &[Self::SenderPairContents],
        dst: &mut [Self::SenderPairContents],
    ) {
        // We can just xor the sender pair (or receiver voles) since that's equivalent to XORing
        // each component pairwise.
        assert_eq!(src_base_voles.len(), 1 << 16);
        for four_uws in dst.chunks_exact_mut(4) {
            let four_uws: [&mut u64; 4] = {
                let (a, extra) = four_uws.split_at_mut(1);
                let (b, extra) = extra.split_at_mut(1);
                let (c, d) = extra.split_at_mut(1);
                debug_assert_eq!(d.len(), 1);
                [&mut a[0], &mut b[0], &mut c[0], &mut d[0]]
            };
            let indices = lpn_indices::matrix_entries_vectorized(lpn_rng);
            four_uws
                .array_zip(indices.array_map(
                    #[inline(always)]
                    |x| <[U16x8; 2]>::from(x),
                ))
                .array_for_each(
                    #[inline(always)]
                    |(dst, [lo, hi])| {
                        let lo0 = U32x4::extending_cast_from(lo);
                        let lo1 = U32x4::extending_cast_from(U16x8::from(
                            U32x4::from(lo).shuffle::<3, 2, 3, 2>(),
                        ));
                        // We use a u64, since we only want two values.
                        let hi = U64x2::extending_cast_from(hi);
                        #[cfg(debug_assertions)]
                        {
                            for (a, b) in lo0
                                .as_array()
                                .iter()
                                .copied()
                                .chain(lo1.as_array().iter().copied())
                                .zip(lo.as_array().iter().copied())
                            {
                                debug_assert_eq!(a, u32::from(b));
                            }
                        }
                        let (lo0, lo1, hi) = unsafe {
                            // SAFETY: all the indices are u16 values, and so are under the length of
                            // src_base_voles
                            let lo0 = U64x4::gather(src_base_voles.as_ptr(), I32x4::from(lo0));
                            let lo1 = U64x4::gather(src_base_voles.as_ptr(), I32x4::from(lo1));
                            let hi = U64x2::gather(src_base_voles.as_ptr(), hi);
                            (lo0, lo1, hi)
                        };
                        let lo = lo0 ^ lo1;
                        let lo = U64x4::from(U32x8::from(lo).shuffle::<1, 0, 3, 2>()) ^ lo;
                        *dst ^= lo.extract::<0>()
                            ^ lo.extract::<2>()
                            ^ hi.extract::<0>()
                            ^ hi.extract::<1>();
                    },
                );
        }
        let remainder = dst.chunks_exact_mut(4).into_remainder();
        let indices = lpn_indices::matrix_entries_vectorized(lpn_rng);
        debug_assert!(remainder.len() <= indices.len());
        for (dst, indices) in remainder.iter_mut().zip(indices.iter()) {
            // Just do them one at-a-time.
            for j in &indices.as_array()[0..10] {
                *dst ^= src_base_voles[(*j) as usize];
            }
        }
    }

    fn lpn_receiver(lpn_rng: &mut AesRng, src_base_voles: &[FE], dst: &mut [FE]) {
        // SAFETY: SmallBinaryField types are repr(transparent) to u64.
        let src_base_voles: &[u64] = unsafe {
            std::slice::from_raw_parts(src_base_voles.as_ptr() as *const _, src_base_voles.len())
        };
        let dst: &mut [u64] =
            unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut _, dst.len()) };
        // The operation of LPN for both the sender and reciever is identical. It's just XORing
        // a u64.
        <Self as FiniteFieldSpecialization<F2, FE>>::lpn_sender(lpn_rng, src_base_voles, dst);
    }

    fn spsvole_receiver_consistency_check_compute_vb(
        rng_chi: &mut AesRng,
        y: FE,
        spsvole_result: &[FE],
    ) -> FE {
        let mut acu = U64x2::ZERO;
        // 8 was choesn since the latency of a CLMUL on Skylake is 7 cycles
        let chunks = spsvole_result.chunks_exact(8);
        let remainder = chunks.remainder();
        let mask = U64x2::broadcast((1 << FE::NumberOfBitsInBitDecomposition::U64) - 1);
        for chunk in chunks {
            let chunk = <&[FE; 8]>::try_from(chunk).expect("We asked for chunks of exactly 8!");
            let chunk = chunk.pair_adjacent().array_map(
                #[inline(always)]
                |(a, b)| U64x2::from([FE::peel(a), FE::peel(b)]),
            );
            let random_bits: [U8x16; 4] = rng_chi.random_bits_custom_size();
            let random_field_elements: [U64x2; 4] = random_bits.array_map(
                #[inline(always)]
                |bits| U64x2::from(bits) & mask,
            );
            let unreduced_products = chunk.array_zip(random_field_elements).array_map(
                #[inline(always)]
                |(spsvole_results, random)| {
                    [
                        spsvole_results.carryless_mul::<false, false>(random),
                        spsvole_results.carryless_mul::<true, true>(random),
                    ]
                },
            );
            unreduced_products.array_for_each(
                #[inline(always)]
                |arr| {
                    arr.array_for_each(
                        #[inline(always)]
                        |x| {
                            acu ^= x;
                        },
                    )
                },
            );
        }
        let acu = FE::reduce(acu);
        <NoSpecialization as FiniteFieldSpecialization<F2, FE>>::
            spsvole_receiver_consistency_check_compute_vb(rng_chi, y, remainder) + acu
    }

    fn spsvole_sender_compute_va(
        rng_chi: &mut AesRng,
        spsvole_result: &[Self::SenderPairContents],
    ) -> (FE, Arr<F2, Degree<FE>>) {
        let mut x_stars = U64x2::ZERO;
        let mut acu = U64x2::ZERO;
        // 8 was choesn since the latency of a CLMUL on Skylake is 7 cycles
        let chunks = spsvole_result.chunks_exact(8);
        let remainder = chunks.remainder();
        let mask = U64x2::broadcast((1 << FE::NumberOfBitsInBitDecomposition::U64) - 1);
        let one = U64x2::broadcast(1);
        for chunk in chunks {
            let chunk = <&[Self::SenderPairContents; 8]>::try_from(chunk)
                .expect("We asked for chunks of exactly 8!");
            let chunk = chunk.pair_adjacent().array_map(
                #[inline(always)]
                |(a, b)| U64x2::from([a, b]),
            );
            let random_bits: [U8x16; 4] = rng_chi.random_bits_custom_size();
            let random_field_elements: [U64x2; 4] = random_bits.array_map(
                #[inline(always)]
                |bits| U64x2::from(bits) & mask,
            );
            let unreduced_products = chunk.array_zip(random_field_elements).array_map(
                #[inline(always)]
                |(spsvole_results, random)| {
                    let u_values = spsvole_results.shift_right::<63>();
                    // We subtract 1 which will broadcast the inverse of the u value (stored in the
                    // high bit of each of the spsvole_results, since it's a sender pair) across
                    // the entire u64. We want to XOR chi/random into x_stars only if u is 1. We
                    // can achieve copee by AND-ing the broadcasted u value with random, and XOR-ing
                    // it. Equivalently, we can take AND(NOT(braodcasted u value), random) and XOR
                    // that with x_stars. Luckily, AVX2 has an ANDNOT instruction.
                    x_stars ^= random.and_not(u_values - one);
                    [
                        (spsvole_results & mask).carryless_mul::<false, false>(random),
                        (spsvole_results & mask).carryless_mul::<true, true>(random),
                    ]
                },
            );
            unreduced_products.array_for_each(
                #[inline(always)]
                |arr| {
                    arr.array_for_each(
                        #[inline(always)]
                        |x| {
                            acu ^= x;
                        },
                    )
                },
            );
        }
        let va = FE::reduce(acu);
        let (va2, mut x_stars2) =
            generic_spsvole_sender_compute_va::<F2, FE, Self>(rng_chi, remainder);
        debug_assert_eq!(
            x_stars.extract::<0>() >> FE::NumberOfBitsInBitDecomposition::U64,
            0
        );
        debug_assert_eq!(
            x_stars.extract::<1>() >> FE::NumberOfBitsInBitDecomposition::U64,
            0
        );
        let x_stars = x_stars.extract::<0>() ^ x_stars.extract::<1>();
        let x_stars = FE::from_lower_bits(x_stars).decompose::<F2>();
        for (x_star2, x_star) in x_stars2.iter_mut().zip(x_stars.iter()) {
            *x_star2 += x_star;
        }
        (va + va2, x_stars2)
    }

    /*fn copee_sender_128(
        inputs_rng: &mut AesRng,
        copee: &mut CopeeSender<FE>,
        io: &mut impl Write,
        _s: &mut <<FE as FiniteField>::PrimeField as CanonicalSerialize>::Serializer,
        dst: &mut Vec<Self::SenderPairContents>,
    ) -> Result<(), crate::Error> {
        let pt = U8x16::from(U64x2::from_array([copee.counter, 0]));
        debug_assert!(copee.aes_objs.len() <= 63);
        let mut matrix = [U8x16::ZERO; 64];
        let [inputs] = inputs_rng.random_bits_custom_size();
        matrix[63] = inputs;
        let mut to_write = [U8x16::ZERO; 64];
        for ((w0, (prf0, prf1)), to_write) in matrix
            .iter_mut()
            .zip(copee.aes_objs.iter())
            .zip(to_write.iter_mut())
        {
            *w0 = prf0.0.encrypt(pt);
            let w1 = prf1.0.encrypt(pt);
            *to_write = *w0 ^ w1 ^ inputs;
        }
        io.write_all(bytemuck::cast_slice(&to_write[0..FE::Degree::USIZE]))?;
        let mut matrix_transposed = [0_u64; 128];
        crate::utils::transpose_pre_allocated(
            bytemuck::bytes_of(&matrix),
            bytemuck::bytes_of_mut(&mut matrix_transposed),
            64,
            128,
        );
        copee.counter += 1;
        dst.extend_from_slice(&matrix_transposed);
        Ok(())
    }

    fn copee_receiver_128(
        copee: &mut CopeeReceiver<FE>,
        io: &mut impl Read,
        _d: &mut <<FE as FiniteField>::PrimeField as CanonicalSerialize>::Deserializer,
        dst: &mut Vec<FE>,
    ) -> Result<(), crate::Error> {
        let pt = U8x16::from(U64x2::from_array([copee.counter, 0]));
        debug_assert!(copee.aes_objs.len() <= 63);
        let mut matrix = [U8x16::ZERO; 64];
        io.read_exact(bytemuck::cast_slice_mut(&mut matrix[0..FE::Degree::USIZE]))?;
        for (i, (row, prf)) in matrix.iter_mut().zip(copee.aes_objs.iter()).enumerate() {
            let w = prf.0.encrypt(pt);
            *row = (row.and_not(U8x16::from(U64x2::broadcast(
                ((copee.first_64_choices >> i) & 1).wrapping_sub(1),
            )))) ^ w;
        }
        let mut matrix_transposed = [0_u64; 128];
        crate::utils::transpose_pre_allocated(
            bytemuck::bytes_of(&matrix),
            bytemuck::bytes_of_mut(&mut matrix_transposed),
            64,
            128,
        );
        copee.counter += 1;
        dst.extend_from_slice(unsafe {
            std::slice::from_raw_parts(matrix_transposed.as_ptr() as *const FE, 128)
        });
        Ok(())
    }*/
}

#[cfg(test)]
fn small_binary_lpn_test<FE: SmallBinaryField>()
where
    F2: IsSubFieldOf<FE>,
{
    use rand::RngCore;
    fn simple_lpn(lpn_rng: &mut AesRng, src_base_voles: &[u64], dst: &mut [u64]) {
        let indices_generator = std::iter::repeat_with(|| {
            IntoIterator::into_iter(lpn_indices::matrix_entries_vectorized(lpn_rng))
        })
        .flatten()
        .map(|idx| <[usize; 10]>::array_generate(|i| idx.as_array()[i] as usize));
        for (indices, dst) in indices_generator.zip(dst.iter_mut()) {
            for idx in indices.iter().copied() {
                *dst ^= src_base_voles[idx];
            }
        }
    }
    for extra in 0..3 {
        let mut rng = AesRng::new();
        let mut src_base_voles = Vec::with_capacity(1 << 16);
        for _ in 0..1 << 16 {
            src_base_voles.push(rng.next_u64());
        }
        let n = 285696 + extra;
        let mut dst = Vec::with_capacity(n);
        for _ in 0..n {
            dst.push(rng.next_u64());
        }
        let mut expected_out = dst.clone();
        let mut actual_out = dst.clone();
        simple_lpn(&mut rng.clone(), &src_base_voles, &mut expected_out);
        <SmallBinaryFieldSpecialization as FiniteFieldSpecialization<F2, FE>>::lpn_sender(
            &mut rng.clone(),
            &src_base_voles,
            &mut actual_out,
        );
        assert_eq!(expected_out, actual_out);
    }
}

#[test]
fn test_f40b_lpn() {
    small_binary_lpn_test::<scuttlebutt::field::F40b>();
}

#[test]
fn test_f56b_lpn() {
    small_binary_lpn_test::<scuttlebutt::field::F56b>();
}

#[test]
fn test_f63b_lpn() {
    small_binary_lpn_test::<scuttlebutt::field::F63b>();
}
