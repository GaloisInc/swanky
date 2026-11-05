use fancy_traits::{Circuit, Fancy, FancyBinary, FancyConstant, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, bail, swanky_error};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{CircuitResult, FieldBackend, HigherDegreeBackend};
use swanky_sieve_ir_parser::WireId;

use crate::higher_degree_commitment::{
    BatchProverAccumulatorF2FLambda, CommitmentPolynomialProver,
};
use crate::parameters::{FLambda, Params};
use crate::proof::ChiGenerator;
use crate::vole::RandomVoleP;

/// Values produced by a completed prover circuit traversal.
pub(crate) struct ProverTraverserParts<Vole, P: Params>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    /// Aggregated degree-0 coefficients.
    pub(crate) degree_0_aggregation: FLambda<P>,
    /// Aggregated degree-1 coefficients.
    pub(crate) degree_1_aggregation: FLambda<P>,
    /// Aggregated assert-zero commitment.
    pub(crate) assert_zero_commitment: FLambda<P>,
    /// Accumulator for the higher-degree constraint polynomials.
    pub(crate) higher_degree_accumulator: BatchProverAccumulatorF2FLambda<P>,
    /// Random VOLE values supplied to the traverser.
    pub(crate) voles: Vole,
}

/// A [`ProverTraverser`] allows the prover to execute the gate-by-gate evaluation portion of the
/// VOLE-in-the-head protocol.
///
/// The primary steps in circuit traversal include assigning VOLEs to each wire and
/// computing the two aggregated values used in the proof.
pub struct ProverTraverser<Vole, P: Params>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    /// Current position for a fresh extended witness value.
    wire_values_pos: WireId,

    /// Map containing the wire values for the extended witness (private inputs and multiplication gates in the circuit).
    extended_witness: Vec<F2>,

    /// Fiat-Shamir challenges as powers of chi. There should be one for each polynomial (e.g. non-linear gate) and assert zero.
    chi_challenge: ChiGenerator<P>,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Count of how many of the custom VOLEs have been assigned.
    vole_assignment_count: usize,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_degree_0: FLambda<P>,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_degree_1: FLambda<P>,

    /// Partial aggregation of the assert zero check.
    /// TODO: Add this to the specification and reference it.
    aggregate_assert_zero: FLambda<P>,

    /// Streamed accumulator for the higher-degree constraint batch.
    higher_degree_accumulator: BatchProverAccumulatorF2FLambda<P>,
}

impl<Vole: RandomVoleP<Params = P>, P: Params> ProverTraverser<Vole, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `extended_witness` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must correspond to the number of polynomials. In this setting, that must
    ///   be no greater than the length of the extended witness (as defined by the [`RandomVole`]);
    /// - The [`RandomVole::extended_witness_length()`] must be large enough to have a VOLE
    ///   corresponding to every gate in the extended witness;
    /// - The `max_higher_degree` must be the maximum degree among the circuit's higher degree
    ///   constraint polynomials (0 if there are none), as computed by
    ///   [`ProverPreparer::max_higher_degree()`](crate::proof::prover_preparer::ProverPreparer::max_higher_degree).
    pub(crate) fn new(
        extended_witness: Vec<F2>,
        chi_challenge: ChiGenerator<P>,
        voles: Vole,
        max_higher_degree: usize,
    ) -> Result<Self> {
        // TODO: debug_assert!(extended_witness.len() == voles.extended_witness_length())
        Ok(Self {
            wire_values_pos: 0,
            extended_witness,
            chi_challenge,

            voles,
            vole_assignment_count: 0,

            aggregate_degree_0: FLambda::<P>::ZERO,
            aggregate_degree_1: FLambda::<P>::ZERO,

            aggregate_assert_zero: FLambda::<P>::ZERO,

            higher_degree_accumulator: BatchProverAccumulatorF2FLambda::new(max_higher_degree),
        })
    }

    fn next_vole(&mut self) -> Result<FLambda<P>> {
        let next_index = self.vole_assignment_count;
        self.vole_assignment_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.voles.extended_witness_length() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: needed at least {} VOLEs, but only got {}",
                self.vole_assignment_count,
                self.voles.extended_witness_length()
            )
        }

        self.voles.vole_mask(next_index)
    }

    /// Decomposes into the aggregate components that we constructed during the
    /// full circuit traversal.
    ///
    /// The components that were passed to [`Self::new()`] are returned unchanged.
    ///
    /// This will fail if there are witness values without a corresponding VOLE. Note that the
    /// VOLEs may contain more correlations than the witness requires; the trailing ones are
    /// reserved for masking the higher degree aggregate (see
    /// [`Proof::prove()`](crate::proof::Proof::prove)).
    pub(crate) fn into_parts(self) -> Result<ProverTraverserParts<Vole, P>> {
        if self.vole_assignment_count != self.extended_witness.len() {
            bail!(
                ErrorKind::OtherError,
                "Traversal did not use exactly one VOLE per extended witness value! Had {}, used {}",
                self.extended_witness.len(),
                self.vole_assignment_count
            );
        }
        Ok(ProverTraverserParts {
            degree_0_aggregation: self.aggregate_degree_0,
            degree_1_aggregation: self.aggregate_degree_1,
            assert_zero_commitment: self.aggregate_assert_zero,
            higher_degree_accumulator: self.higher_degree_accumulator,
            voles: self.voles,
        })
    }

    /// Get the next extended witness value.
    pub(crate) fn next_witness_value(&mut self) -> Result<F2> {
        let wid = self.wire_values_pos;
        self.wire_values_pos += 1;

        self.extended_witness
            .get::<usize>(
                wid.try_into()
                    .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e}"))?,
            )
            .ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Internal invariant failed: expected a witness value for wire ID {}",
                    wid
                )
            })
            .copied()
    }

    /// Run `circuit` using [`ProverTraverser`].
    pub(crate) fn execute<C: Circuit<Self, Input = ()>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(self, (), channel)?;
            Ok(())
        })
    }
}

/// An [`F2`] element alongside its associated VOLE tag.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire<P: Params>(F2, FLambda<P>);

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl<VOLE: RandomVoleP<Params = P>, P: Params> FieldBackend<F2> for ProverTraverser<VOLE, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    type Wire = (F2, FLambda<P>);

    fn input_public(&mut self) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `input_public`")
    }

    fn input_private(&mut self) -> Result<Self::Wire> {
        let f = self.next_witness_value()?;
        let vole = self.next_vole()?;
        // Private input gates don't define a polynomial that would contribute to the aggregated
        // coefficients being computed
        Ok((f, vole))
    }

    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        let res = lhs.0 + rhs.0;
        // Compute the correct VOLE for the output wire
        let sum_vole = lhs.1 + rhs.1;
        // Linear gates don't contribute to the aggregated values being computed
        Ok((res, sum_vole))
    }

    fn addc(&mut self, lhs: &Self::Wire, rhs: F2) -> Result<Self::Wire> {
        Ok((lhs.0 + rhs, lhs.1))
    }

    fn mul(&mut self, left: &Self::Wire, right: &Self::Wire) -> Result<Self::Wire> {
        let f = self.next_witness_value()?;

        // Assign a fresh VOLE to the output wire and get the corresponding challenge
        let vole = self.next_vole()?;
        let challenge = self.chi_challenge.next();

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let degree_0_coeff = left.1 * right.1;
        let degree_1_coeff = P::f2_scale(right.0, left.1) + P::f2_scale(left.0, right.1) - vole;

        self.aggregate_degree_0 += challenge * degree_0_coeff;
        self.aggregate_degree_1 += challenge * degree_1_coeff;

        Ok((f, vole))
    }

    fn mulc(&mut self, _: &Self::Wire, _: F2) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `mulc`")
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        let challenge = self.chi_challenge.next();
        self.aggregate_assert_zero += challenge * wire.1;
        Ok(())
    }
}

impl<VOLE: RandomVoleP<Params = P>, P: Params> Fancy for ProverTraverser<VOLE, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    type Item = Wire<P>;
}

impl<VOLE: RandomVoleP<Params = P>, P: Params> FancyConstant<F2> for ProverTraverser<VOLE, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn constant(&mut self, constant: F2) -> Self::Item {
        Wire(constant, FLambda::<P>::ZERO)
    }
}

impl<VOLE: RandomVoleP<Params = P>, P: Params> FancyBinary for ProverTraverser<VOLE, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let res = x.0 + y.0;

        // Compute the correct VOLE for the output wire
        let sum_vole = x.1 + y.1;

        // Linear gates don't contribute to the aggregated values being computed
        Wire(res, sum_vole)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        let f = self.next_witness_value()?;

        // Assign a fresh VOLE to the output wire and get the corresponding challenge
        let vole = self.next_vole()?;
        let challenge = self.chi_challenge.next();

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let degree_0_coeff = x.1 * y.1;
        let degree_1_coeff = P::f2_scale(y.0, x.1) + P::f2_scale(x.0, y.1) - vole;

        self.aggregate_degree_0 += challenge * degree_0_coeff;
        self.aggregate_degree_1 += challenge * degree_1_coeff;

        Ok(Wire(f, vole))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        Wire(x.0 + F2::ONE, x.1)
    }
}

impl<VOLE: RandomVoleP<Params = P>, P: Params> FancyZeroKnowledge<F2> for ProverTraverser<VOLE, P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn witness(&mut self, _: &mut Channel) -> Result<Self::Item> {
        let f = self.next_witness_value()?;
        let vole = self.next_vole()?;

        // Private input gates don't define a polynomial that would contribute to the aggregated
        // coefficients being computed
        Ok(Wire(f, vole))
    }

    fn assert_zero(&mut self, value: &Self::Item, _: &mut Channel) -> Result<()> {
        let challenge = self.chi_challenge.next();
        self.aggregate_assert_zero += challenge * value.1;
        Ok(())
    }
}

impl<Vole: RandomVoleP<Params = P>, P: Params> HigherDegreeBackend<F2, P::FLambda>
    for ProverTraverser<Vole, P>
where
    F2: IsSubFieldOf<P::FLambda>,
{
    type HigherDegreeWire = CommitmentPolynomialProver<F2, P::FLambda>;

    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.add(rhs))
    }

    fn h_addc(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: F2,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.addc(rhs))
    }

    fn h_mul(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.mul(rhs))
    }

    fn h_mulc(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: F2,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.mulc(rhs))
    }

    fn assert_zero_higher_degree<const INPUT_LEN: usize>(
        &mut self,
        inputs: &[Self::Wire; INPUT_LEN],
        f: impl Fn(&Self, [Self::HigherDegreeWire; INPUT_LEN]) -> CircuitResult<Self::HigherDegreeWire>,
    ) -> CircuitResult<()> {
        // Build the input commitments and evaluate the constraint over them.
        let constraint = f(
            self,
            std::array::from_fn(|i| {
                CommitmentPolynomialProver::from_base_vole(inputs[i].0, inputs[i].1)
            }),
        )?;

        // Consume the next shared Fiat–Shamir weight and add this constraint to the batch.
        let challenge = self.chi_challenge.next();
        self.higher_degree_accumulator
            .push_constraint(&constraint, challenge)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::Binary128Bit;
    use merlin::Transcript;
    use rand::rng;

    use crate::vole::insecure::InsecureVole;
    use swanky_field_binary::F128b;

    type Traverser = ProverTraverser<InsecureVole<Binary128Bit>, Binary128Bit>;

    fn test_traverser(chi: F128b, max_higher_degree: usize) -> Traverser {
        let rng = &mut rng();
        let transcript = &mut Transcript::new(b"higher degree tests");
        let secret: Vec<F2> = Vec::new();
        let (voles, _challenge) = InsecureVole::create(0, transcript, &secret, rng);

        ProverTraverser::new(Vec::new(), ChiGenerator::new(chi), voles, max_higher_degree).unwrap()
    }

    /// The aggregate must commit to zero and be consistent with the verifier's view: evaluating
    /// it at any point Δ must match the challenge-weighted, degree-aligned sum of the constraints
    /// computed homomorphically over the wire tags q_i = w_i + x_i·Δ.
    #[test]
    fn higher_degree_aggregate_matches_homomorphic_evaluation() {
        let rng = &mut rng();
        let chi = F128b::random(rng);
        let mut traverser = test_traverser(chi, 4);

        // Witness satisfying x0 * x1 * x2 * x3 == 0, a degree-4 constraint.
        let product_values = [F2::ONE, F2::ONE, F2::ZERO, F2::ONE];
        let product_wires: [(F2, F128b); 4] =
            std::array::from_fn(|i| (product_values[i], F128b::random(rng)));
        traverser
            .assert_zero_higher_degree(&product_wires, |b, x| {
                let x01 = b.h_mul(&x[0], &x[1])?;
                let x23 = b.h_mul(&x[2], &x[3])?;
                b.h_mul(&x01, &x23)
            })
            .unwrap();

        // Witness satisfying x0 * x1 + x2 * x3 == 0, a degree-2 constraint.
        let sum_values = [F2::ONE; 4];
        let sum_wires: [(F2, F128b); 4] =
            std::array::from_fn(|i| (sum_values[i], F128b::random(rng)));
        traverser
            .assert_zero_higher_degree(&sum_wires, |b, x| {
                let x01 = b.h_mul(&x[0], &x[1])?;
                let x23 = b.h_mul(&x[2], &x[3])?;
                b.h_add(&x01, &x23)
            })
            .unwrap();

        let ProverTraverserParts {
            higher_degree_accumulator: accumulator,
            ..
        } = traverser.into_parts().unwrap();

        // The aggregate is aligned to the maximum constraint degree (4), and its highest-degree
        // coefficient still commits to zero.
        assert_eq!(accumulator.max_degree(), 4);
        assert_eq!(accumulator.top_coefficient(), F128b::ZERO);

        // Evaluate at a random Δ and compare against the verifier's computation
        // sum_i chi_i * Δ^(d - d_i) * γ_i, with γ_i derived from the tags q_i = w_i + x_i·Δ.
        let delta = F128b::random(rng);
        let tag = |(x, w): (F2, F128b)| w + x * delta;

        let gamma_product = product_wires.map(tag).iter().fold(F128b::ONE, |a, q| a * q);
        let sum_tags = sum_wires.map(tag);
        let gamma_sum = sum_tags[0] * sum_tags[1] + sum_tags[2] * sum_tags[3];

        let evaluated = accumulator.evaluate_at(delta);
        let expected = chi * gamma_product + chi * chi * delta * delta * gamma_sum;
        assert_eq!(evaluated, expected);
    }

    /// Constant operations apply the constant to the committed value.
    #[test]
    fn constant_operations_apply_to_the_committed_value() {
        let rng = &mut rng();
        let traverser = test_traverser(F128b::random(rng), 0);
        let poly = CommitmentPolynomialProver::from_base_vole(F2::ONE, F128b::random(rng));

        let sum = traverser.h_addc(&poly, F2::ONE).unwrap();
        assert_eq!(sum.highest_degree(), F2::ZERO);
        let scaled = traverser.h_mulc(&poly, F2::ZERO).unwrap();
        assert_eq!(scaled.highest_degree(), F2::ZERO);
    }
}
