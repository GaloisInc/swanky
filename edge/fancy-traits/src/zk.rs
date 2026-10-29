use crate::Fancy;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteField;

/// Extension trait for [`crate::Fancy`] supporting operations used for
/// zero-knowledge proofs.
pub trait FancyZeroKnowledge<FF: FiniteField>: Fancy {
    /// Encode a witness value.
    ///
    /// As this is used by both the prover and the verifier, it assumes the
    /// prover has some "witness tape" in which it can read its witnesses from.
    fn witness(&mut self, channel: &mut Channel) -> Result<Self::Item>;

    /// Assert that `x == 0`.
    fn assert_zero(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<()>;
}
