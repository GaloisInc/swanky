use super::AesRng;
use vectoreyes::{
    array_utils::{ArrayAdjacentPairs, ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    Aes128EncryptOnly, AesBlockCipher, SimdBase, SimdBase32, SimdBase64, U32x4, U32x8, U64x4,
};

/// Sample `u32`s uniformly from `[0, bound)`.
#[derive(Debug, Clone, Copy)]
pub struct UniformIntegersUnderBound {
    threshold: u32,
    bound: u32,
}

impl UniformIntegersUnderBound {
    /// Create the distribution.
    ///
    /// # Performance
    /// This function performs very well as long as the bound, $`b`$ is such that $`t(b)`$ is small,
    /// where:
    /// ```math
    /// t(b) = (2^{32} - b + 1) \mod b
    /// ```
    ///
    /// In particular, the probability that a random vector of $`N`$ elements is accepted is:
    /// ```math
    /// \left(1 - \frac{t(b)}{2^{32}}\right)^N
    /// ```
    /// Thus, if $`t(b)`$ is quite small, then it is efficient for us to reject $`N`$ elements at a
    /// time, as opposed to rejecting individual elements.
    /// # Repeated Invocations
    /// It is inefficient to repeatedly call `new` with a fresh `bound`. However, an alternative
    /// algorithm has not yet been implemented.
    /// # Timing Side-Channel
    /// `bound` should be a _public_ value, since it may be leaked in the timing of sampling.
    /// # Panics
    /// Panics if `bound` is `0`.
    // TODO: implement Lemire's "Nearly Divisionless" algorithm, too.
    #[inline]
    pub fn new(bound: u32) -> Self {
        assert_ne!(bound, 0);
        let threshold = 0_u32.wrapping_sub(bound) % bound;
        UniformIntegersUnderBound { threshold, bound }
    }

    /// The exclusive bound of the integers produced by this generator.
    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Produce `Aes128EncryptOnly::BLOCK_COUNT_HINT * 4` uniformly distributed `u32`s (under the
    /// given bound).
    #[inline(always)]
    pub fn sample(&self, rng: &mut AesRng) -> [U32x8; Aes128EncryptOnly::BLOCK_COUNT_HINT / 2] {
        debug_assert_eq!(Aes128EncryptOnly::BLOCK_COUNT_HINT % 2, 0);
        const N: usize = Aes128EncryptOnly::BLOCK_COUNT_HINT;
        const HALF_N: usize = Aes128EncryptOnly::BLOCK_COUNT_HINT / 2;
        self.lemire_body::<N, HALF_N>(rng)
    }

    /// Produce 20 uniformly distributed `u32`s under the given bound.
    ///
    /// Random numbers are returned in `out[0][..]`, `out[1][..]`, and the even-indexed entries of
    /// `out[2]` (i.e. `out[2][0]`, `out[2][2]`, `out[2][4]`, `out[2][6]`).
    ///
    /// # Alternatives
    /// Consider using [Self::sample] instead. It may be faster on some platforms.
    #[inline(always)]
    pub fn sample_20(&self, rng: &mut AesRng) -> [U32x8; 3] {
        const N: usize = 5;
        const HALF_N: usize = 3;
        self.lemire_body::<N, HALF_N>(rng)
    }

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
    fn lemire_body<const N: usize, const HALF_N: usize>(&self, rng: &mut AesRng) -> [U32x8; HALF_N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N> + UnrollableArraySize<HALF_N>,
        [U32x8; N]: ArrayAdjacentPairs<T = U32x8, AdjacentPairs = [(U32x8, U32x8); HALF_N]>,
    {
        let range = U64x4::broadcast(self.bound as u64);
        let t = U32x8::broadcast(self.threshold);
        loop {
            let rand_bits = rng.random_bits_custom_size::<N>();
            let x = rand_bits.array_map(
                #[inline(always)]
                |x| U64x4::from(U32x4::from(x)),
            );
            let m = x.array_map(
                #[inline(always)]
                |x| U32x8::from(x.mul_lo(range)),
            );
            let m_interleaved = m.array_map(
                #[inline(always)]
                |m| m.shuffle::<3, 1, 2, 0>(),
            );
            let m_lo = m_interleaved
                .pair_adjacent_maybe_odd(U32x8::broadcast(u32::MAX))
                .array_map(
                    #[inline(always)]
                    |(a, b)| a.unpack_lo(b),
                );
            let l = m_lo;
            // We reject and try again if any element in l is less than self.threshold.
            // In other words, we reject if the min(every element in l, self.threshold) != threshold
            if l.array_fold(
                t,
                #[inline(always)]
                |a, b| a.min(b),
            ) != t
            {
                continue;
            }
            let m_hi = m_interleaved
                .pair_adjacent_maybe_odd(U32x8::ZERO)
                .array_map(
                    #[inline(always)]
                    |(a, b)| a.unpack_hi(b),
                );
            break m_hi;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Block;
    use proptest::prelude::*;
    use rand_core::SeedableRng;

    // The 500_000 bound is chosen somewhat arbitrarily, to make sure that the thresholds aren't
    // too big.

    proptest! {
        #[test]
        fn lemire_within_bounds(
            seed in any::<[u8; 16]>(),
            bound in 1..=500_000_u32,
        ) {
            let mut rng = AesRng::from_seed(Block::from(seed));
            let dist = UniformIntegersUnderBound::new(bound);
            for x in dist.sample(&mut rng).iter().copied() {
                for y in x.as_array().iter().copied() {
                    prop_assert!(y < bound);
                }
            }
        }
    }

    proptest! {
        #[test]
        fn lemire_20_within_bounds(
            seed in any::<[u8; 16]>(),
            bound in 1..=500_000_u32,
        ) {
            let mut rng = AesRng::from_seed(Block::from(seed));
            let dist = UniformIntegersUnderBound::new(bound);
            let out = dist.sample_20(&mut rng);
            for (i,x) in out.iter().copied().enumerate() {
                for (j,y) in x.as_array().iter().copied().enumerate() {
                    if i == 2 && (j % 2) == 1 {
                        prop_assert_eq!(y, 0);
                    }
                    prop_assert!(y < bound);
                }
            }
        }
    }
}
