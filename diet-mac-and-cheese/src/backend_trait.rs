#![allow(clippy::clone_on_copy)]

//! Core backend trait used for Diet Mac'n'Cheese.

use eyre::Result;
use scuttlebutt::field::FiniteField;

/// An interface for computing over basic gates using a single [`FiniteField`].
pub trait BackendT {
    /// The type associated with the input and output wires of the gates.
    type Wire;
    /// The [`FiniteField`] the computation is operating over.
    type FieldElement: FiniteField;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement>;
    fn one(&self) -> Result<Self::FieldElement>;
    fn zero(&self) -> Result<Self::FieldElement>;
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire>;
    fn challenge(&mut self) -> Result<Self::Wire>;

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()>;

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire>;

    fn finalize(&mut self) -> Result<()>;
    fn reset(&mut self);
}
