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
use eyre::{ensure, Result};
use generic_array::typenum::Unsigned;
use log::warn;
use swanky_field::{FiniteField, FiniteRing};

mod less_than_eq;
pub(crate) use less_than_eq::less_than_eq_with_public;
use swanky_party::Party;

/// A dot product gadget computing `xs · ys`, where `xs` contains MAC'd values
/// and `ys` contains public values.
///
/// This gadget works over all fields.
pub(crate) fn dotproduct_with_public<P: Party, B: BackendT<P>>(
    backend: &mut B,
    xs: &[B::Wire],
    ys: &[B::FieldElement],
) -> Result<B::Wire> {
    let mut result = backend.input_public(B::FieldElement::ZERO)?;
    for (x, y) in xs.iter().zip(ys.iter()) {
        let tmp = backend.mul_constant(x, *y)?;
        result = backend.add(&result, &tmp)?;
    }
    Ok(result)
}

/// A permutation check gadget that asserts that `xs = 𝛑(ys)`, erroring out if
/// not.
///
/// This gadget currently only works over fields larger than the statistical
/// security parameter (which we have harded at 40 bits).
pub(crate) fn permutation_check<P: Party, B: BackendT<P>>(
    backend: &mut B,
    xs: &[B::Wire],
    ys: &[B::Wire],
    ntuples: usize,
    tuple_size: usize,
) -> Result<()> {
    // TODO: turn this warning into an error once F2 becomes supported with extension fields
    if !(<B::FieldElement as FiniteField>::NumberOfBitsInBitDecomposition::USIZE >= 40) {
        warn!("Insecure use of permutation check: Field size must be >= 40 bits");
    }

    ensure!(xs.len() == ys.len(), "Input lengths are not equal",);
    ensure!(
        xs.len() == ntuples * tuple_size,
        "Provided input length not equal to expected input length",
    );

    let minus_one = -B::FieldElement::ONE;
    let random = backend.random()?;

    // TODO: Better would be to generate random values using `random` as a seed.
    let mut acc = random;
    let mut challenges = vec![B::FieldElement::ZERO; tuple_size];
    for challenge in challenges.iter_mut() {
        *challenge = acc;
        acc = random * random;
    }

    let challenge = backend.random()?;

    let mut x = backend.constant(B::FieldElement::ONE)?;
    for i in 0..ntuples {
        let result = dotproduct_with_public::<P, B>(
            backend,
            &xs[i * tuple_size..(i + 1) * tuple_size],
            &challenges,
        )?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        x = backend.mul(&x, &tmp)?;
    }
    let mut y = backend.constant(B::FieldElement::ONE)?;
    for i in 0..ntuples {
        let result = dotproduct_with_public::<P, B>(
            backend,
            &ys[i * tuple_size..(i + 1) * tuple_size],
            &challenges,
        )?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        y = backend.mul(&y, &tmp)?;
    }
    let z = backend.sub(&x, &y)?;
    backend.assert_zero(&z)
}
