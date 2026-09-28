//! Pseudorandom number generators (PRNGs) for use in Swanky.
//!
//! [`SwankyRng`] is the prefered PRNG to use, although the underlying PRNG may
//! change depending on the platform and/or future changes to this library. If
//! you need a _specific_ PRNG, these can be accessed as well. Currently, there
//! are two:
//! - [`Aes128Rng`]: A PRNG based on AES128-CTR mode.
//! - [`Aes256Rng`]: A PRNG based on AES256-CTR mode.
#![deny(missing_docs)]

use rand_core::Infallible;

mod aesrng;
#[deprecated(note = "use Aes128Rng or Aes256Rng instead")]
pub use aesrng::Aes128Rng as AesRng;
pub use aesrng::{Aes128Rng, Aes256Rng};
mod vectorized;
use rand::{SeedableRng, TryCryptoRng, TryRng};
pub use vectorized::UniformIntegersUnderBound;

/// Swanky's preferred pseudorandom number generator.
///
/// This is currently a thin wrapper around [`Aes128Rng`], although that is subject
/// to change in the future and/or depending on the platform. See the
/// documentation of [`Aes128Rng`] for any performance considerations.
#[derive(Default)]
pub struct SwankyRng(Aes128Rng);

impl SwankyRng {
    /// Create a new [`SwankyRng`] using a random seed from [`rand::random`].
    pub fn new() -> Self {
        Self(Aes128Rng::new())
    }
}

impl core::fmt::Debug for SwankyRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SwankyRng").finish()
    }
}

impl TryRng for SwankyRng {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }
    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }
    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}

impl SeedableRng for SwankyRng {
    type Seed = <Aes128Rng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self(Aes128Rng::from_seed(seed))
    }
}

impl TryCryptoRng for SwankyRng {}
