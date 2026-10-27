use crate::Fancy;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteField;

/// Extension trait for [`crate::Fancy`] supporting operations used for
/// zero-knowledge proofs.
pub trait FancyZeroKnowledge<FF: FiniteField>: Fancy {
    /// Assert that `x == 0`.
    fn assert_zero(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<()>;
}
