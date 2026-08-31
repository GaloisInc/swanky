//! Pseudorandom number generators (PRNGs) used in Swanky.
//!
//! [`SwankyRng`] is the prefered PRNG to use, although the underlying PRNG may
//! change depending on the platform and/or future changes to this library. If
//! you need a _specific_ PRNG, these can be accessed as well. Currently, there
//! is only one:
//! - [`AesRng`]: A PRNG based on AES-CTR mode.
#![deny(missing_docs)]
use rand_core::Infallible;

mod aesrng;
pub use aesrng::AesRng;
mod vectorized;
use rand::{SeedableRng, TryCryptoRng, TryRng};
pub use vectorized::UniformIntegersUnderBound;

/// Swanky's preferred pseudorandom number generator.
///
/// This is currently a thin wrapper around [`AesRng`], although that is subject
/// to change in the future and/or depending on the platform. See the
/// documentation of [`AesRng`] for any performance considerations.
#[derive(Debug, Default)]
pub struct SwankyRng(AesRng);

impl SwankyRng {
    /// Create a new [`SwankyRng`] using a random seed from [`rand::random`].
    pub fn new() -> Self {
        Self(AesRng::new())
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
    type Seed = <AesRng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self(AesRng::from_seed(seed))
    }
}

impl TryCryptoRng for SwankyRng {}
