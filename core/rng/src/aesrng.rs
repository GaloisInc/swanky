use rand::{
    SeedableRng, TryCryptoRng, TryRng,
    rand_core::{
        Infallible,
        block::{BlockRng, Generator},
    },
};
use vectoreyes::{
    Aes128EncryptOnly, Aes256EncryptOnly, AesBlockCipher, U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

/// Construct an AES-based RNG using [`BlockRng`]. The `aes` parameter should be an implementer of
/// `AesBlockCipher` and `core` should be constructed with `make_aes_rng_core` using the same `aes`.
macro_rules! make_aes_rng {
    (
        $(#[$doc:meta])*
        $name:ident {
            aes = $aes:ty,
            core = $core:ty $(,)?
        }
    ) => {
        $(#[$doc])*
        pub struct $name(BlockRng<$core>);

        impl TryRng for $name {
            type Error = Infallible;

            #[inline]
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(self.0.next_word())
            }
            #[inline]
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(self.0.next_u64_from_u32())
            }
            #[inline]
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                self.0.fill_bytes(dest);
                Ok(())
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple(stringify!($name)).finish()
            }
        }

        impl SeedableRng for $name {
            type Seed = <$core as SeedableRng>::Seed;

            fn from_seed(seed: Self::Seed) -> Self {
                $name(BlockRng::new(<$core>::from_seed(seed)))
            }
        }

        impl TryCryptoRng for $name {}

        impl $name {
            /// Create a new [`Self`] using a random seed from [`rand::random`].
            #[inline]
            pub fn new() -> Self {
                let seed: <$aes as AesBlockCipher>::Key = rand::random();
                $name::from_seed(seed)
            }

            /// Create a new [`Self`] using a given seed and IV.
            ///
            /// # Security considerations
            /// One must be careful to avoid situations where the same seed is used, and
            /// the IVs either match or are sufficiently close, as this could produce
            /// identical RNG outputs!
            pub fn from_seed_and_iv(seed: <$aes as AesBlockCipher>::Key, iv: u128) -> Self {
                Self(BlockRng::new(<$core>::from_seed_and_iv(seed, iv)))
            }

            /// Generate [`Aes128EncryptOnly::BLOCK_COUNT_HINT`] random [`U8x16`]s.
            #[inline(always)]
            pub fn random_u8x16s(&mut self) -> [U8x16; <$aes>::BLOCK_COUNT_HINT] {
                self.0.core.gen_rand_bits()
            }

            /// Generate `N` random [`U8x16`]s.
            ///
            /// # Alternatives
            /// Consider using [`Self::random_u8x16s`] for an optimal choice of `N`.
            #[inline(always)]
            pub fn random_u8x16s_custom_size<const N: usize>(&mut self) -> [U8x16; N]
            where
                ArrayUnrolledOps: UnrollableArraySize<N>,
            {
                self.0.core.gen_rand_bits()
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self::new()
            }
        }
    }
}

/// Create the core of an AES-based using [`BlockRng`] that implements Generator and SeedableRng.
/// The `aes` parameter must implement [`aes::cipher::BlockCipherEncrypt`].
macro_rules! make_aes_rng_core {
    (
        $(#[$doc:meta])*
        $name:ident {
            aes = $aes:ty,
        }
    ) => {
        $(#[$doc])*
        pub struct $name {
            aes: $aes,
            counter: u128,
        }

        impl $name {
            fn from_seed_and_iv(seed: <$aes as AesBlockCipher>::Key, iv: u128) -> Self {
                let mut rng = Self::from_seed(seed);
                rng.counter = iv;
                rng
            }

            #[inline(always)]
            fn gen_rand_bits<const N: usize>(&mut self) -> [U8x16; N]
            where
                ArrayUnrolledOps: UnrollableArraySize<N>,
            {
                let blocks = <[U8x16; N]>::array_generate(
                    #[inline(always)]
                    |_| {
                        let ctr = self.counter.into();
                        self.counter += 1;
                        ctr
                    },
                );
                self.aes.encrypt_many(blocks)
            }
        }

        impl Generator for $name {
            type Output = [u32; <$aes>::BLOCK_COUNT_HINT * 4];

            // Compute `E(state)` four times, where `state` is a counter.
            #[inline]
            fn generate(&mut self, results: &mut Self::Output) {
                *results = bytemuck::cast(self.gen_rand_bits::<{ <$aes>::BLOCK_COUNT_HINT }>());
            }
        }

        impl SeedableRng for $name {
            type Seed = <$aes as AesBlockCipher>::Key;

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                $name {
                    aes: <$aes>::new_with_key(seed),
                    counter: 0,
                }
            }
        }
    }
}

make_aes_rng! {
    /// Pseudorandom number generator based on fixed-key 128-bit AES.
    ///
    /// This uses AES-CTR mode with the initial seed acting as the AES key, and the
    /// counter always starting at zero. To set the counter to some other value, use
    /// [`Aes128Rng::from_seed_and_iv`].
    ///
    /// # Performance considerations
    /// If needing to generate an array of `u8`s, it is significantly more
    /// performant (around 2x) to use `Aes128Rng::fill_bytes` over `Aes128Rng::random`.
    /// This is because `AesRng::random::<[u8; N]>` consumes `N` `u32`s, whereas
    /// `Aes128Rng::fill_bytes` consumes `N / 4` `u32`s.
    ///
    /// If needing to generate a [`U8x16`], `Aes128Rng::random::<U8x16>` is the most
    /// performant: around 3x faster than using `Aes128Rng::fill_bytes` followed by a
    /// conversion.
    Aes128Rng {
        aes = Aes128EncryptOnly,
        core = Aes128RngCore,
    }
}

make_aes_rng_core! {
    /// The core of [`Aes128Rng`], used with [`BlockRng`].
    Aes128RngCore {
        aes = Aes128EncryptOnly,
    }
}

make_aes_rng! {
    /// Pseudorandom number generator based on fixed-key 256-bit AES.
    ///
    /// This uses AES-CTR mode with the initial seed acting as the AES key, and the
    /// counter always starting at zero. To set the counter to some other value, use
    /// [`Aes256Rng::from_seed_and_iv`].
    ///
    /// # Performance considerations
    /// If needing to generate an array of `u8`s, it is significantly more
    /// performant (around 2x) to use `Aes256Rng::fill_bytes` over `Aes256Rng::random`.
    /// This is because `AesRng::random::<[u8; N]>` consumes `N` `u32`s, whereas
    /// `Aes256Rng::fill_bytes` consumes `N / 4` `u32`s.
    ///
    /// If needing to generate a [`U8x16`], `Aes256Rng::random::<U8x16>` is the most
    /// performant: around 3x faster than using `Aes256Rng::fill_bytes` followed by a
    /// conversion.
    Aes256Rng {
        aes = Aes256EncryptOnly,
        core = Aes256RngCore,
    }
}

make_aes_rng_core! {
    /// The core of [`Aes256Rng`], used with [`BlockRng`].
    Aes256RngCore {
        aes = Aes256EncryptOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128Enc, Aes256Enc,
        cipher::{Array, BlockCipherEncrypt, KeyInit},
    };
    use rand::{Rng, RngExt, rng};

    macro_rules! make_tests {
        (
            mod $name:ident {
                aes_rng = $aes_rng:ty,
                aes_enc = $aes_enc:ty,
                seed_bytes = $seed_bytes:literal $(,)?
            }
        ) => {
            mod $name {
                use super::*;

                #[test]
                fn works_like_aes() {
                    let seed = rng().random::<[u8; $seed_bytes]>();

                    let mut rng = <$aes_rng>::from_seed(seed.into());
                    let aes = <$aes_enc>::new(&Array::from(seed));

                    for i in 0..1000u128 {
                        // Note: This is _not_ the same as `rng.random::<[u8; 16]>()`!
                        // `rng.random` generates 16 `u32` words and keeps the low byte of
                        // each.
                        let mut left = [0u8; 16];
                        rng.fill_bytes(&mut left);

                        let mut right = Array::from(i.to_le_bytes());
                        aes.encrypt_block(&mut right);

                        assert_eq!(left, right, "block {i} doesn't match");
                    }
                }

                #[test]
                fn u8x16_same_as_fill_bytes() {
                    let seed = rng().random::<[u8; $seed_bytes]>();

                    let mut rng1 = <$aes_rng>::from_seed(seed.into());
                    let mut rng2 = <$aes_rng>::from_seed(seed.into());

                    for i in 0..1000u128 {
                        let mut left = [0u8; 16];
                        rng1.fill_bytes(&mut left);

                        let right = rng2.random::<U8x16>();

                        assert_eq!(U8x16::from(left), right, "block {i} doesn't match");
                    }
                }

                #[test]
                fn from_seed_same_as_from_seed_and_iv_0() {
                    let seed = rng().random::<[u8; $seed_bytes]>();

                    let mut rng1 = <$aes_rng>::from_seed(seed.into());
                    let mut rng2 = <$aes_rng>::from_seed_and_iv(seed.into(), 0);

                    for i in 0..1000u128 {
                        assert_eq!(
                            rng1.random::<U8x16>(),
                            rng2.random::<U8x16>(),
                            "block {i} doesn't match"
                        );
                    }
                }
            }
        };
    }

    make_tests! {
        mod aes_128_rng {
            aes_rng = Aes128Rng,
            aes_enc = Aes128Enc,
            seed_bytes = 16,
        }
    }

    make_tests! {
        mod aes_256_rng {
            aes_rng = Aes256Rng,
            aes_enc = Aes256Enc,
            seed_bytes = 32,
        }
    }
}
