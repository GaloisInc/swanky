use rand::{
    SeedableRng, TryCryptoRng, TryRng,
    rand_core::{
        Infallible,
        block::{BlockRng, Generator},
    },
};
use vectoreyes::{
    Aes256EncryptOnly, AesBlockCipher, U8x16, U8x32,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

/// Pseudorandom number generator based on fixed-key AES.
///
/// This uses AES-CTR mode with the initial seed acting as the AES key, and the
/// counter always starting at zero. To set the counter to some other value, use
/// [`Aes256Rng::from_seed_and_iv`].
///
/// NOTE: This implementation was cloned from the 128-bit AesRng with minimal
/// alterations. See aesrng.rs for more notes. In the future, we may want to
/// make [`crate::AesRng`] generic over the key size instead.
#[derive(Debug)]
pub struct Aes256Rng(BlockRng<Aes256RngCore>);

impl TryRng for Aes256Rng {
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

impl SeedableRng for Aes256Rng {
    type Seed = <Aes256RngCore as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Aes256Rng(BlockRng::new(Aes256RngCore::from_seed(seed)))
    }
}

impl TryCryptoRng for Aes256Rng {}

impl Aes256Rng {
    /// Create a new [`Aes256Rng`] using a random seed from [`rand::random`].
    #[inline]
    pub fn new() -> Self {
        let seed: U8x32 = rand::random();
        Aes256Rng::from_seed(seed)
    }

    /// Create a new [`Aes256Rng`] using a given seed and IV.
    pub fn from_seed_and_iv(seed: U8x32, iv: u128) -> Self {
        Self(BlockRng::new(Aes256RngCore::from_seed_and_iv(seed, iv)))
    }

    /// Generate random bits.
    #[inline(always)]
    pub fn random_bits(&mut self) -> [U8x16; Aes256EncryptOnly::BLOCK_COUNT_HINT] {
        // FIXME (maybe): This advances the counter directly, bypassing BlockRng's buffer. This
        // means the buffer is not used by this function and will continue to contain earlier
        // blocks. Interleaving this and [`BlockRng::fill_bytes`] will result in out-of-order
        // blocks. Inherited from [`crate::AesRng`], and maybe intentional for performance (avoiding
        // a memcpy).
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

impl Default for Aes256Rng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of [`Aes256Rng`], used with [`BlockRng`].
#[derive(Debug)]
pub struct Aes256RngCore {
    aes: Aes256EncryptOnly,
    counter: u128,
}

impl Aes256RngCore {
    fn from_seed_and_iv(seed: U8x32, iv: u128) -> Self {
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

impl Generator for Aes256RngCore {
    type Output = [u32; Aes256EncryptOnly::BLOCK_COUNT_HINT * 4];

    // Compute `E(state)` four times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Output) {
        *results = bytemuck::cast(self.gen_rand_bits::<{ Aes256EncryptOnly::BLOCK_COUNT_HINT }>());
    }
}

impl SeedableRng for Aes256RngCore {
    type Seed = U8x32;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        Aes256RngCore {
            aes: Aes256EncryptOnly::new_with_key(seed),
            counter: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes256Enc,
        cipher::{Array, BlockCipherEncrypt, KeyInit},
    };
    use rand::{Rng, RngExt, rng};

    #[test]
    fn aes_rng_works_like_aes() {
        let seed = rng().random::<[u8; 32]>();

        let mut rng = Aes256Rng::from_seed(seed.into());
        let aes = Aes256Enc::new(&Array::from(seed));

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

    /// Check that [`Aes256Rng::from_seed_and_iv`] starts the CTR counter at `iv`.
    ///
    /// This pins down two things the other tests don't reach: that the IV really is used as the
    /// initial counter value, and the byte order in which the counter is handed to AES. The IVs
    /// below are chosen so that incrementing the counter carries out of a 32- and a 64-bit word
    /// boundary, which is exactly what distinguishes a 128-bit counter from a narrower one (see
    /// the note on `Aes256RngCore::gen_rand_bits` about the endianness of this counter).
    #[test]
    fn aes_rng_with_iv_works_like_aes() {
        let seed = rng().random::<[u8; 32]>();
        let aes = Aes256Enc::new(&Array::from(seed));

        let ivs = [
            0,
            1,
            // Carries out of the low 32-bit word...
            u32::MAX as u128 - 1,
            // ...out of the low 64-bit word...
            u64::MAX as u128 - 1,
            // ...and a high word that must be left alone. (Deliberately not `u128::MAX`: this
            // counter can't be incremented past the end without overflowing.)
            ((u64::MAX as u128) << 64) | 1,
            rng().random::<u128>(),
        ];

        for iv in ivs {
            let mut rng = Aes256Rng::from_seed_and_iv(seed.into(), iv);

            for i in 0..1000u128 {
                let mut left = [0u8; 16];
                rng.fill_bytes(&mut left);

                let mut right = Array::from((iv + i).to_le_bytes());
                aes.encrypt_block(&mut right);

                assert_eq!(left, right, "iv {iv:#034x}, block {i} doesn't match");
            }
        }
    }

    /// The seed-only constructor is documented as starting the counter at zero.
    #[test]
    fn from_seed_matches_zero_iv() {
        let seed = rng().random::<[u8; 32]>();

        let mut rng1 = Aes256Rng::from_seed(seed.into());
        let mut rng2 = Aes256Rng::from_seed_and_iv(seed.into(), 0);

        for i in 0..1000u128 {
            assert_eq!(
                rng1.random::<U8x16>(),
                rng2.random::<U8x16>(),
                "block {i} doesn't match"
            );
        }
    }

    #[test]
    fn aes_rng_u8x16_same_as_fill_bytes() {
        let seed = rng().random::<[u8; 32]>();

        let mut rng1 = Aes256Rng::from_seed(seed.into());
        let mut rng2 = Aes256Rng::from_seed(seed.into());

        for i in 0..1000u128 {
            let mut left = [0u8; 16];
            rng1.fill_bytes(&mut left);

            let right = rng2.random::<U8x16>();

            assert_eq!(U8x16::from(left), right, "block {i} doesn't match");
        }
    }
}
