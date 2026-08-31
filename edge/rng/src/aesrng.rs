use rand::{
    SeedableRng, TryCryptoRng, TryRng,
    rand_core::{
        Infallible,
        block::{BlockRng, Generator},
    },
};
use vectoreyes::{
    Aes128EncryptOnly, AesBlockCipher, U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

/// Pseudorandom number generator based on fixed-key AES.
///
/// This uses AES-CTR mode with the initial seed acting as the AES key, and the
/// counter always starting at zero. To set the counter to some other value, use
/// [`AesRng::from_seed_and_iv`].
///
/// # Performance considerations
/// If needing to generate an array of `u8`s, it is significantly more
/// performant (around 2x) to use `AesRng::fill_bytes` over `AesRng::random`.
/// This is because `AesRng::random::<[u8; N]>` consumes `N` `u32`s, whereas
/// `AesRng::fill_bytes` consumes `N / 4` `u32`s.
///
/// If needing to generate a [`U8x16`], `AesRng::random::<U8x16>` is the most
/// performant: around 3x faster than using `AesRng::fill_bytes` followed by a
/// conversion.
#[derive(Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl TryRng for AesRng {
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

impl SeedableRng for AesRng {
    type Seed = <AesRngCore as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::new(AesRngCore::from_seed(seed)))
    }
}

impl TryCryptoRng for AesRng {}

impl AesRng {
    /// Create a new [`AesRng`] using a random seed from [`rand::random`].
    #[inline]
    pub fn new() -> Self {
        let seed: U8x16 = rand::random();
        AesRng::from_seed(seed)
    }

    /// Create a new [`AesRng`] using a given seed and IV.
    pub fn from_seed_and_iv(seed: U8x16, iv: u128) -> Self {
        Self(BlockRng::new(AesRngCore::from_seed_and_iv(seed, iv)))
    }

    /// Generate random bits.
    #[inline(always)]
    pub fn random_bits(&mut self) -> [U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT] {
        self.0.core.gen_rand_bits()
    }

    /// Generate `N * 128` random bits.
    ///
    /// # Alternatives
    /// Consider using [Self::random_bits] instead.
    #[inline(always)]
    pub fn random_bits_custom_size<const N: usize>(&mut self) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        self.0.core.gen_rand_bits()
    }
}

impl Default for AesRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of [`AesRng`], used with [`BlockRng`].
#[derive(Debug)]
pub struct AesRngCore {
    aes: Aes128EncryptOnly,
    counter: u128,
}

impl AesRngCore {
    fn from_seed_and_iv(seed: U8x16, iv: u128) -> Self {
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

impl Generator for AesRngCore {
    type Output = [u32; Aes128EncryptOnly::BLOCK_COUNT_HINT * 4];

    // Compute `E(state)` four times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Output) {
        *results = bytemuck::cast(self.gen_rand_bits::<{ Aes128EncryptOnly::BLOCK_COUNT_HINT }>());
    }
}

impl SeedableRng for AesRngCore {
    type Seed = U8x16;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRngCore {
            aes: Aes128EncryptOnly::new_with_key(seed),
            counter: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128Enc,
        cipher::{Array, BlockCipherEncrypt, KeyInit},
    };
    use rand::{Rng, RngExt, rng};

    #[test]
    fn aes_rng_works_like_aes() {
        let seed = rng().random::<[u8; 16]>();

        let mut rng = AesRng::from_seed(seed.into());
        let aes = Aes128Enc::new(&Array::from(seed));

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
    fn aes_rng_u8x16_same_as_fill_bytes() {
        let seed = rng().random::<[u8; 16]>();

        let mut rng1 = AesRng::from_seed(seed.into());
        let mut rng2 = AesRng::from_seed(seed.into());

        for i in 0..1000u128 {
            let mut left = [0u8; 16];
            rng1.fill_bytes(&mut left);

            let right = rng2.random::<U8x16>();

            assert_eq!(U8x16::from(left), right, "block {i} doesn't match");
        }
    }
}
