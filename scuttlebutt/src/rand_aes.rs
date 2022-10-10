//! Fixed-key AES random number generator.

use crate::Block;
use rand::{CryptoRng, Error, Rng, RngCore, SeedableRng};
use rand_core::block::{BlockRng64, BlockRngCore};
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    Aes128EncryptOnly, AesBlockCipher, SimdBase, U64x2, U8x16,
};

pub mod vectorized;

/// Implementation of a random number generator based on fixed-key AES.
///
/// This uses AES in a counter-mode-esque way, but with the counter always
/// starting at zero. When used as a PRNG this is okay [TODO: citation?].
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng64<AesRngCore>);

impl RngCore for AesRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl SeedableRng for AesRng {
    type Seed = <AesRngCore as SeedableRng>::Seed;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng64::<AesRngCore>::from_seed(seed))
    }
    #[inline]
    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng64::<AesRngCore>::from_rng(rng).map(AesRng)
    }
}

impl CryptoRng for AesRng {}

impl AesRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    #[inline]
    pub fn new() -> Self {
        let seed = rand::random::<Block>();
        AesRng::from_seed(seed)
    }

    /// Create a new RNG using a random seed from this one.
    #[inline]
    pub fn fork(&mut self) -> Self {
        let seed = self.gen::<Block>();
        AesRng::from_seed(seed)
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

/// The core of `AesRng`, used with `BlockRng`.
#[derive(Clone, Debug)]
pub struct AesRngCore {
    aes: Aes128EncryptOnly,
    // Overflowing a u64 would take well over 2^64 nanoseconds, which is over 500 years!
    counter: u64,
}

impl AesRngCore {
    #[inline(always)]
    fn gen_rand_bits<const N: usize>(&mut self) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        let blocks = <[U8x16; N]>::array_generate(
            #[inline(always)]
            |_| {
                let x = self.counter;
                self.counter += 1;
                U8x16::from(U64x2::set_lo(x))
            },
        );
        self.aes.encrypt_many(blocks)
    }
}

impl BlockRngCore for AesRngCore {
    type Item = u64;
    type Results = [u64; Aes128EncryptOnly::BLOCK_COUNT_HINT * 2];

    // Compute `E(state)` eight times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        *results = bytemuck::cast(self.gen_rand_bits::<{ Aes128EncryptOnly::BLOCK_COUNT_HINT }>());
    }
}

impl SeedableRng for AesRngCore {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRngCore {
            aes: Aes128EncryptOnly::new_with_key(seed.0),
            counter: 0,
        }
    }
}

impl CryptoRng for AesRngCore {}

impl From<AesRngCore> for AesRng {
    #[inline]
    fn from(core: AesRngCore) -> Self {
        AesRng(BlockRng64::new(core))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_generate() {
        let mut rng = AesRng::new();
        let a = rng.gen::<[Block; 8]>();
        let b = rng.gen::<[Block; 8]>();
        assert_ne!(a, b);
    }
}
