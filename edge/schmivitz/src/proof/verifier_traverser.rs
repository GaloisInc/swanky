use fancy_traits::{Circuit, Fancy, FancyBinary, FancyConstant, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{CircuitResult, FieldBackend, HigherDegreeBackend};

use crate::higher_degree_commitment::{
    BatchVerifierAccumulatorF2FLambda, CommitmentPolynomialVerifier,
};
use crate::parameters::{FLambda, Params};
use crate::proof::ChiGenerator;

/// Values produced by a completed verifier circuit traversal.
pub(crate) struct VerifierTraverserParts<P: Params>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    /// Partial construction of the verifier's aggregated commitment.
    pub(crate) validation_aggregate: FLambda<P>,
    /// Aggregated assert-zero value.
    pub(crate) aggregate_assert_zero: FLambda<P>,
    /// Accumulator for the higher-degree constraint evaluations.
    pub(crate) higher_degree_accumulator: BatchVerifierAccumulatorF2FLambda<P>,
}

/// A [`VerifierTraverser`] allows the verifier to execute the gate-by-gate evaluation portion of
/// the VOLE-in-the-head verification protocol.
///
/// The primary steps in circuit traversal are assigning masked witnesses to each
/// wire (either using provided witnesses from the proof or evaluating expected witnesses for
/// linear gates) and computing the aggregate value used to verify the proof.
pub struct VerifierTraverser<P: Params>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    /// Fiat-Shamir challenges as powers of chi. There should be one for each polynomial (e.g. non-linear gate) and assert zero.
    chi_challenge: ChiGenerator<P>,

    /// Verifier's chosen random VOLE key ($`\Delta`$ in the paper).
    verifier_key: FLambda<P>,

    /// The masked witness commitments ($`\bf q'`$ in the paper).
    ///
    /// There should be one of these for each extended witness.
    /// Note that these are a function of the random VOLEs correlated with the witness, the
    /// commitment to the witness itself, and the verifier's VOLE key.
    masked_witnesses: Vec<FLambda<P>>,

    /// Count of how many of the provided masked witnesses have been assigned.
    assigned_witness_count: usize,

    /// Partial aggregation of the value $`\tilde c`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $`\sum_{i \in [t]} \chi_i \cdot c_i(\Delta)`$.
    aggregate: FLambda<P>,

    /// Partial aggregation of the assert zero check.
    /// TODO: Add this to the specification and reference it.
    aggregate_assert_zero: FLambda<P>,

    /// Streamed accumulator for the higher-degree constraint batch, grouped by degree.
    higher_degree_accumulator: BatchVerifierAccumulatorF2FLambda<P>,
}

impl<P: Params> VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    pub(crate) fn new(
        chi_challenge: ChiGenerator<P>,
        verifier_key: FLambda<P>,
        masked_witnesses: Vec<FLambda<P>>,
        max_higher_degree: usize,
    ) -> Result<Self> {
        // TODO: Add additional asserts here?
        Ok(Self {
            chi_challenge,
            verifier_key,
            masked_witnesses,
            assigned_witness_count: 0,
            aggregate: FLambda::<P>::ZERO,
            aggregate_assert_zero: FLambda::<P>::ZERO,
            higher_degree_accumulator: BatchVerifierAccumulatorF2FLambda::new(max_higher_degree),
        })
    }

    /// Assign a wire ID to the next unused masked witness and get the corresponding challenge.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_masked_witness()`] to
    /// assign a specific witness value to a linear gate.
    ///
    /// Fails if there aren't enough unused witnesses or if the [`WireId`] is already assigned to
    /// a masked witness.
    fn next_masked_witness(&mut self) -> Result<FLambda<P>> {
        let next_index = self.assigned_witness_count;
        self.assigned_witness_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: needed at least {} masked witnesses, but only got {}",
                self.assigned_witness_count,
                self.masked_witnesses.len()
            )
        }

        Ok(self.masked_witnesses[next_index])
    }

    /// Decomposes into the aggregate components (a partial construction of `c~` and the higher
    /// degree aggregates) that were built during full circuit traversal.
    ///
    /// This will fail if there were unused challenges or masked witnesses.
    pub(crate) fn into_parts(self) -> Result<VerifierTraverserParts<P>> {
        if self.assigned_witness_count != self.masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Proof contained more masked witnesses than it needed! Had {}, used {}",
                self.masked_witnesses.len(),
                self.assigned_witness_count
            );
        }
        Ok(VerifierTraverserParts {
            validation_aggregate: self.aggregate,
            aggregate_assert_zero: self.aggregate_assert_zero,
            higher_degree_accumulator: self.higher_degree_accumulator,
        })
    }

    /// Run `circuit` using [`VerifierTraverser`].
    pub(crate) fn execute<C: Circuit<Self, Input = ()>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(self, (), channel)?;
            Ok(())
        })
    }
}

/// An [`FLambda`] element representing a VOLE tag.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire<P: Params>(FLambda<P>);

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl<P: Params> FieldBackend<F2> for VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    type Wire = FLambda<P>;

    fn input_public(&mut self) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `input_public`")
    }

    fn input_private(&mut self) -> Result<Self::Wire> {
        self.next_masked_witness()
    }

    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        Ok(*lhs + *rhs)
    }

    fn addc(&mut self, lhs: &Self::Wire, rhs: F2) -> Result<Self::Wire> {
        // Compute the correct masked witness for the output wire
        let t = if rhs == F2::ZERO {
            FLambda::<P>::ZERO
        } else {
            FLambda::<P>::ONE
        };
        Ok(*lhs - t * self.verifier_key)
    }

    fn mul(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        // Assign the next masked witness to the destination wire
        let res = self.next_masked_witness()?;
        let challenge = self.chi_challenge.next();

        // Compute the contibution to the aggregate: ci​(Δ) = q_left * ​q_right ​− q_dst * ​Δ
        let eval = *lhs * *rhs - (res * self.verifier_key);

        self.aggregate += challenge * eval;

        Ok(res)
    }

    fn mulc(&mut self, _: &Self::Wire, _: F2) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `mulc`")
    }

    fn assert_zero(&mut self, arg: &Self::Wire) -> Result<()> {
        let challenge = self.chi_challenge.next();

        self.aggregate_assert_zero += challenge * *arg;
        Ok(())
    }
}

impl<P: Params> Fancy for VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    type Item = Wire<P>;
}

impl<P: Params> FancyConstant<F2> for VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn constant(&mut self, constant: F2) -> Self::Item {
        let value = if constant == F2::ONE {
            FLambda::<P>::ONE
        } else {
            FLambda::<P>::ZERO
        };
        Wire(-value * self.verifier_key)
    }
}

impl<P: Params> FancyBinary for VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        Wire(x.0 + y.0)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        // Assign the next masked witness to the destination wire
        let res = self.next_masked_witness()?;
        let challenge = self.chi_challenge.next();

        // Compute the contibution to the aggregate: ci​(Δ) = q_left * ​q_right ​− q_dst * ​Δ
        let eval = x.0 * y.0 - (res * self.verifier_key);

        self.aggregate += challenge * eval;

        Ok(Wire(res))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        Wire(x.0 - FLambda::<P>::ONE * self.verifier_key)
    }
}

impl<P: Params> FancyZeroKnowledge<F2> for VerifierTraverser<P>
where
    F2: IsSubFieldOf<FLambda<P>>,
{
    fn witness(&mut self, _: &mut Channel) -> Result<Self::Item> {
        // Assign a fresh masked witness to the wire
        let res = self.next_masked_witness()?;

        // Private input gates don't define a polynomial that would contribute to the aggregate
        // being computed, so we ignore the challenge
        Ok(Wire(res))
    }

    fn assert_zero(&mut self, value: &Self::Item, _: &mut Channel) -> Result<()> {
        let challenge = self.chi_challenge.next();

        self.aggregate_assert_zero += challenge * value.0;
        Ok(())
    }
}
impl<P: Params> HigherDegreeBackend<F2, P::FLambda> for VerifierTraverser<P>
where
    F2: IsSubFieldOf<P::FLambda>,
{
    /// A verifier commitment carrying its evaluation and degree.
    type HigherDegreeWire = CommitmentPolynomialVerifier<F2, P::FLambda>;

    /// Mirrors
    /// [`CommitmentPolynomialVerifier::add`] on verifier commitments.
    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.add(rhs, self.verifier_key))
    }

    /// Mirrors
    /// [`CommitmentPolynomialVerifier::addc`] on verifier commitments.
    fn h_addc(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: F2,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs.addc(rhs, self.verifier_key))
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
        // Treat each masked witness as a degree-one verifier-side commitment.
        let constraint = f(
            self,
            std::array::from_fn(|i| CommitmentPolynomialVerifier::from_base_vole(inputs[i])),
        )?;

        // Consume the next shared Fiat–Shamir weight and add this evaluation to the batch.
        let challenge = self.chi_challenge.next();
        self.higher_degree_accumulator
            .push_constraint(&constraint, challenge)?;
        Ok(())
    }
}
