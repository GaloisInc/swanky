#![allow(clippy::clone_on_copy)]

//! Core backend trait used for Diet Mac'n'Cheese.

use eyre::Result;
use mac_n_cheese_sieve_parser::Number;
use scuttlebutt::field::{FiniteField, PrimeFiniteField};
use std::any::type_name;

/// Helper function to convert [`Number`]s to [`PrimeFiniteField`] values.
pub(crate) fn prime_field_value_from_number<FE: PrimeFiniteField>(&val: &Number) -> Result<FE> {
    let x = FE::try_from_int(val);
    if x.is_none().into() {
        eyre::bail!(
            "{val} is too large to be an element of {}",
            type_name::<FE>()
        )
    } else {
        // Safe: We've already checked that x is not none.
        Ok(x.unwrap())
    }
}

/// An interface for computing over basic gates using a single [`FiniteField`].
pub trait BackendT {
    /// The type associated with the input and output wires of the gates.
    type Wire;
    /// The [`FiniteField`] the computation is operating over.
    type FieldElement: FiniteField;

    fn from_number(val: &Number) -> Result<Self::FieldElement>;
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
