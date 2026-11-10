//! Core backend trait used for Diet Mac'n'Cheese.

use crate::mac::MacT;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteField;

/// An interface for computing a proof over a single [`FiniteField`].
pub trait BackendT {
    /// The type associated with the input and output wires of the gates.
    type Wire: MacT;
    /// The [`FiniteField`] the computation is operating over.
    type FieldElement: FiniteField;

    /// Return the value from a wire when it is a prover.
    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement>;
    /// Return a copy of `wire`.
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire>;
    /// Return a random [`Self::FieldElement`].
    fn random(&mut self, channel: &mut Channel) -> Result<Self::FieldElement>;
    /// Return `val` as a [`Self::Wire`].
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    /// Assert that `wire` is zero.
    fn assert_zero(&mut self, wire: &Self::Wire, channel: &mut Channel) -> Result<()>;

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire, channel: &mut Channel) -> Result<Self::Wire>;
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn input_private(
        &mut self,
        val: Option<Self::FieldElement>,
        channel: &mut Channel,
    ) -> Result<Self::Wire>;

    /// Finalize the internal checks.
    fn finalize(&mut self, channel: &mut Channel) -> Result<()>;
}
