//! Core backend trait used for Diet Mac'n'Cheese.

use crate::mac::MacT;
use eyre::Result;
use mac_n_cheese_sieve_parser::Number;
use std::any::type_name;
use swanky_field::{FiniteField, PrimeFiniteField};
use swanky_party::Party;

/// An interface for computing a proof over a single [`FiniteField`].
pub trait BackendT<P: Party> {
    /// The type associated with the input and output wires of the gates.
    type Wire: MacT;
    /// The [`FiniteField`] the computation is operating over.
    type FieldElement: FiniteField;

    /// Return the value from a wire when it is a prover.
    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement>;
    /// Return [`Self::FieldElement::ONE`].
    fn one(&self) -> Result<Self::FieldElement>;
    /// Return [`Self::FieldElement::ZERO`].
    fn zero(&self) -> Result<Self::FieldElement>;
    /// Return a copy of `wire`.
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire>;
    /// Return a random [`Self::FieldElement`].
    fn random(&mut self) -> Result<Self::FieldElement>;
    /// Return `val` as a [`Self::Wire`].
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    /// Assert that `wire` is zero.
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()>;

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire>;

    /// Finalize the internal checks.
    fn finalize(&mut self) -> Result<()>;
}

/// Backends that admit a conversion from [`Number`] to the underlying field
/// element type.
pub trait PrimeBackendT<P: Party>: BackendT<P> {
    /// Try to convert a [`Number`] to a `Self::FieldElement`.
    fn from_number(val: &Number) -> Result<Self::FieldElement>;
}

/// Blanket implementation of `PrimeBackendT` for all types whose `FieldElement`
/// is a `PrimeFiniteField`.
impl<P: Party, T: BackendT<P>> PrimeBackendT<P> for T
where
    T::FieldElement: PrimeFiniteField,
{
    fn from_number(&val: &Number) -> Result<Self::FieldElement> {
        let x = T::FieldElement::try_from_int(val);
        if x.is_none().into() {
            eyre::bail!(
                "{val} is too large to be an element of {}",
                type_name::<T::FieldElement>()
            )
        } else {
            // Safe: We've already checked that x is not none.
            Ok(x.unwrap())
        }
    }
}
