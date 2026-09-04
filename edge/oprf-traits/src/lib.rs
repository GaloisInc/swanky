#![deny(missing_docs)]
//! Base traits impl-ed by all our OPRF implementations

use rand::CryptoRng;
use swanky_channel_legacy::AbstractChannel;
use swanky_error::Result;

/// Trait containing the associated types used by an oblivious PRF.
pub trait ObliviousPrf
where
    Self: Sized,
{
    /// PRF seed.
    type Seed: Sized;
    /// PRF input.
    type Input: Sized;
    /// PRF output.
    type Output: Sized;
}

/// Trait for an oblivious PRF sender.
pub trait Sender: ObliviousPrf
where
    Self: Sized,
{
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng>(channel: &mut C, rng: &mut RNG) -> Result<Self>;
    /// Runs `m` OPRF instances as the sender, returning the OPRF seeds.
    fn send<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Seed>>;
    /// Computes the oblivious PRF on seed `seed` and input `input`.
    fn compute(&self, seed: Self::Seed, input: Self::Input) -> Self::Output;
}

/// Trait for an oblivious PRF receiver.
pub trait Receiver: ObliviousPrf
where
    Self: Sized,
{
    /// Runs any one-time initialization.
    fn init<C: AbstractChannel, RNG: CryptoRng>(channel: &mut C, rng: &mut RNG) -> Result<Self>;
    /// Runs the oblivious PRF on inputs `inputs`, returning the OPRF outputs.
    fn receive<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>>;
}
