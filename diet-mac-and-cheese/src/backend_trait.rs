#![allow(clippy::clone_on_copy)]

//! Core backend trait used for Diet Mac'n'Cheese.

use eyre::Result;
use mac_n_cheese_sieve_parser::Number;
use std::any::type_name;
use swanky_field::{FiniteField, PrimeFiniteField};

/// An interface for computing over basic gates using a single [`FiniteField`].
pub trait BackendT {
    /// The type associated with the input and output wires of the gates.
    type Wire;
    /// The [`FiniteField`] the computation is operating over.
    type FieldElement: FiniteField;

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

/// Backends that admit a conversion from [`Number`] to the underlying field
/// element type.
pub trait PrimeBackendT: BackendT {
    /// Try to convert a [`Number`] to a `Self::FieldElement`.
    fn from_number(val: &Number) -> Result<Self::FieldElement>;
}

/// Blanket implementation of `PrimeBackendT` for all types whose `FieldElement`
/// is a `PrimeFiniteField`.
impl<T: BackendT> PrimeBackendT for T
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
