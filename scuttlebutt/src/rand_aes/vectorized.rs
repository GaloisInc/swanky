use super::AesRng;
use vectoreyes::{
    array_utils::{ArrayAdjacentPairs, ArrayUnrolledExt},
    Aes128EncryptOnly, AesBlockCipher, SimdBase, SimdBase32, SimdBase64, U32x4, U32x8, U64x4,
    U8x16,
};

// NOTE: these techniques can also be extended to random number generation with a non-constant
// upper-bound. However, if the bound is not known in advance, you might need to make different
// choices. This is important when, for example, speeding up a Fisher-Yates shuffle.
// See https://www.pcg-random.org/posts/bounded-rands.html
// See https://lemire.me/blog/2019/06/06/nearly-divisionless-random-integer-generation-on-various-systems/
// See https://github.com/colmmacc/s2n/blob/7ad9240c8b9ade0cc3a403a732ba9f1289934abd/utils/s2n_random.c#L187
// See https://twitter.com/colmmacc/status/1311092454909599744
// See https://github.com/apple/swift/pull/25286
// This is an implementation of "Debiased Integer Multiplication — Lemire's Method"
// See https://www.pcg-random.org/posts/bounded-rands.html
#[inline(always)]
fn lemire_inner_loop(
    rand_bits: [U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT],
    t: U32x8,
    range: U64x4,
) -> Option<[U32x8; Aes128EncryptOnly::BLOCK_COUNT_HINT / 2]> {
    let x = rand_bits.array_map(
        #[inline(always)]
        |x| U64x4::from(U32x4::from(x)),
    );
    let m = x.array_map(
        #[inline(always)]
        |x| U32x8::from(x.mul_lo(range)),
    );
    let m_only_lo = m.array_map(
        #[inline(always)]
        |m| m.shuffle::<2, 0, 2, 0>(),
    );
    let m_lo = m_only_lo.pair_adjacent().array_map(
        #[inline(always)]
        |(a, b)| a.unpack_lo(b),
    );
    let l = m_lo;
    // We reject if l < t.
    if !l
        .array_fold(
            U32x8::ZERO,
            #[inline(always)]
            |acu, l| acu | l.cmp_gt(t),
        )
        .is_zero()
    {
        let m_only_hi = m.array_map(
            #[inline(always)]
            |m| m.shuffle::<3, 1, 3, 1>(),
        );
        // It doesn't matter whether we use hi or lo here.
        let m_hi = m_only_hi.pair_adjacent().array_map(
            #[inline(always)]
            |(a, b)| a.unpack_hi(b),
        );
        Some(m_hi)
    } else {
        None
    }
}
#[inline(always)]
fn lemire_params(bound: u32) -> (U32x8, U64x4) {
    let t = 0_u32.wrapping_sub(bound) % bound;
    let t = U32x8::broadcast(t);
    let range = U64x4::broadcast(bound as u64);
    (t, range)
}

#[inline(always)]
pub fn uniform_integers_under_bound<const BOUND: u32>(
    rng: &mut AesRng,
) -> [U32x8; Aes128EncryptOnly::BLOCK_COUNT_HINT / 2] {
    debug_assert_eq!(Aes128EncryptOnly::BLOCK_COUNT_HINT % 2, 0);
    if BOUND == 0 {
        panic!("The bound cannot be zero!")
    } else if BOUND == 1 {
        Default::default()
    } else {
        let (t, range) = lemire_params(BOUND);
        loop {
            if let Some(out) = lemire_inner_loop(rng.random_bits(), t, range) {
                break out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn lemire_within_bounds(
            rand_bits in any::<[[u8; 16]; Aes128EncryptOnly::BLOCK_COUNT_HINT]>(),
            bound in any::<u32>(),
        ) {
            let (t, range) = lemire_params(bound);
            if let Some(out) = lemire_inner_loop(bytemuck::cast(rand_bits), t, range) {
                for o in out.iter() {
                    for x in o.as_array().iter().copied() {
                        prop_assert!(x < bound);
                    }
                }
            }
        }
    }
}
