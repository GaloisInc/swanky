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

    /// Read a fixed number of witness values.
    fn witnesses<const N: usize>(&mut self, channel: &mut Channel) -> Result<[Self::Item; N]> {
        let mut values = core::array::from_fn(|_| Self::Item::default());
        for value in &mut values {
            *value = self.witness(channel)?;
        }
        Ok(values)
    }

    /// Assert that `x == 0`.
    fn assert_zero(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<()>;
}

/// Extension trait for [`FancyZeroKnowledge`] supporting higher-degree zero constraints.
/// Operations inside a constraint compose higher-degree wires without creating
/// ordinary multiplication extended witnesses.
///
/// # Example
/// ```
/// use fancy_traits::{Circuit, FancyHigherDegree};
/// use swanky_channel::Channel;
/// use swanky_error::Result;
/// use swanky_field_binary::F2;
///
/// struct ProductZeroExample;
/// impl<B: FancyHigherDegree<F2>> Circuit<B> for ProductZeroExample {
///     type Input = ();
///     type Output = ();
///
///     fn execute(&self, backend: &mut B, _: (), channel: &mut Channel) -> Result<()> {
///         let inputs = backend.witnesses::<4>(channel)?;
///         let inputs_h = inputs.map(|wire| backend.to_higher_degree_wire(wire));
///         let x01 = backend.h_mul(&inputs_h[0], &inputs_h[1]);
///         let x23 = backend.h_mul(&inputs_h[2], &inputs_h[3]);
///         let zero = backend.h_mul(&x01, &x23);
///         backend.h_assert_zero(zero)
///     }
/// }
/// ```
pub trait FancyHigherDegree<FF: FiniteField>: FancyZeroKnowledge<FF> {
    /// Representation of a wire inside a higher-degree constraint.
    type HigherDegreeWire;

    /// Convert a [`Fancy::Item`] into a [`Self::HigherDegreeWire`].
    fn to_higher_degree_wire(&self, wire: Self::Item) -> Self::HigherDegreeWire;

    /// Add two higher-degree wires.
    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> Self::HigherDegreeWire;

    /// Add a constant to a higher-degree wire.
    fn h_addc(&self, lhs: &Self::HigherDegreeWire, rhs: FF) -> Self::HigherDegreeWire;

    /// Multiply two higher-degree wires.
    fn h_mul(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> Self::HigherDegreeWire;

    /// Multiply a higher-degree wire by a constant.
    fn h_mulc(&self, lhs: &Self::HigherDegreeWire, rhs: FF) -> Self::HigherDegreeWire;

    /// Assert the wire is zero.
    fn h_assert_zero(&mut self, wire: Self::HigherDegreeWire) -> Result<()>;
}
