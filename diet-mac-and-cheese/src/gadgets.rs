//! This module contains a collection of circuit gadgets.
//!
//! A circuit gadget implements some computation over a (possibly
//! type-constrained) [`BackendT`]. Each gadget is encapsulated in a trait to
//! allow reusing the gadget between both the prover and the verifier.
//!
//! To "enable" a gadget for a particular implementation of [`BackendT`], add
//! the appropriate `impl GadgetName for Backend`.
//!
//! Note! A significant limitation of this design is when we need to
//! "specialize" a gadget to a particular field. For example, we need a
//! specialized gadget for a permutation check on [`F2`]. This is not possible
//! with the current design, so for something like [`F2`] we need to revert to
//! the old "copy-the-code-between-the-prover-and-verifier" approach, which is
//! not ideal. A potential fix for this is to move to using a `Party` trait
//! instead of having separate `Prover` and `Verifier` implementations. However,
//! this is a much larger refactor, and will take time. So for now, if we need
//! specialization, we copy-and-paste.

use crate::backend_trait::BackendT;
use eyre::Result;
use swanky_field::FiniteRing;

mod less_than_eq;
pub(crate) use less_than_eq::less_than_eq_with_public;

mod permutation_check;
pub(crate) use permutation_check::{permutation_check, permutation_check_binary};

/// A dot product gadget computing `xs · [y, y^2, ..., y^n]`, where `xs`
/// contains MAC'd values and `ys` contains public values.
///
/// This gadget works over all fields.
pub(crate) fn dotproduct_with_public_powers<B: BackendT>(
    backend: &mut B,
    xs: &mut impl Iterator<Item = B::Wire>,
    y: B::FieldElement,
    n: usize,
) -> Result<B::Wire> {
    let mut result = backend.input_public(B::FieldElement::ZERO)?;
    let mut acc = y;
    for x in xs.take(n) {
        let tmp = backend.mul_constant(&x, acc)?;
        result = backend.add(&result, &tmp)?;
        acc *= y;
    }
    Ok(result)
}
