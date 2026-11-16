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
///         backend.assert_zero_higher_degree(&inputs, |b, x| {
///             let x01 = b.h_mul(&x[0], &x[1])?;
///             let x23 = b.h_mul(&x[2], &x[3])?;
///             b.h_mul(&x01, &x23)
///         }, channel)
///     }
/// }
/// ```
pub trait FancyHigherDegree<FF: FiniteField>: FancyZeroKnowledge<FF> {
    /// Representation of a wire inside a higher-degree constraint.
    type HigherDegreeWire;

    /// Add two higher-degree wires.
    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> Result<Self::HigherDegreeWire>;

    /// Add a constant to a higher-degree wire.
    fn h_addc(&self, lhs: &Self::HigherDegreeWire, rhs: FF) -> Result<Self::HigherDegreeWire>;

    /// Multiply two higher-degree wires.
    fn h_mul(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> Result<Self::HigherDegreeWire>;

    /// Multiply a higher-degree wire by a constant.
    fn h_mulc(&self, lhs: &Self::HigherDegreeWire, rhs: FF) -> Result<Self::HigherDegreeWire>;

    /// Assert that the callback's higher-degree constraint is zero.
    /// The callback must be a circuit using the operations from this trait.
    fn assert_zero_higher_degree<const INPUT_LEN: usize>(
        &mut self,
        inputs: &[Self::Item; INPUT_LEN],
        f: impl Fn(&Self, [Self::HigherDegreeWire; INPUT_LEN]) -> Result<Self::HigherDegreeWire>,
        channel: &mut Channel,
    ) -> Result<()>;
}
