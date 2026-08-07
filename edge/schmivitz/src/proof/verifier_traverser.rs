use fancy_traits::{
    Circuit, Fancy, FancyBinary, FancyBinaryConstant, FancyEncode, FancyZeroKnowledge, HasModulus,
};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use swanky_sieve_ir_api::FieldBackend;

use crate::proof::ChiGenerator;

/// A [`VerifierTraverser`] allows the verifier to execute the gate-by-gate evaluation portion of
/// the VOLE-in-the-head verification protocol.
///
/// The primary steps in circuit traversal are assigning masked witnesses to each
/// wire (either using provided witnesses from the proof or evaluating expected witnesses for
/// linear gates) and computing the aggregate value used to verify the proof.
pub struct VerifierTraverser {
    /// Fiat-Shamir challenges as powers of chi. There should be one for each polynomial (e.g. non-linear gate) and assert zero.
    chi_challenge: ChiGenerator,

    /// Verifier's chosen random VOLE key ($`\Delta`$ in the paper).
    verifier_key: F128b,

    /// The masked witness commitments ($`\bf q'`$ in the paper).
    ///
    /// There should be one of these for each extended witness.
    /// Note that these are a function of the random VOLEs correlated with the witness, the
    /// commitment to the witness itself, and the verifier's VOLE key.
    masked_witnesses: Vec<F128b>,

    /// Count of how many of the provided masked witnesses have been assigned.
    assigned_witness_count: usize,

    /// Partial aggregation of the value $`\tilde c`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $`\sum_{i \in [t]} \chi_i \cdot c_i(\Delta)`$.
    aggregate: F128b,

    /// Partial aggregation of the assert zero check.
    /// TODO: Add this to the specification and reference it.
    aggregate_assert_zero: F128b,
}

impl VerifierTraverser {
    pub(crate) fn new(
        chi_challenge: ChiGenerator,
        verifier_key: F128b,
        masked_witnesses: Vec<F128b>,
    ) -> Result<Self> {
        // TODO: Add additional asserts here?
        Ok(Self {
            chi_challenge,
            verifier_key,
            masked_witnesses,
            assigned_witness_count: 0,
            aggregate: F128b::ZERO,
            aggregate_assert_zero: F128b::ZERO,
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
    fn next_masked_witness(&mut self) -> Result<F128b> {
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

    /// Decomposes into the aggregate component (a partial construction of `c~`) that was built
    /// during full circuit traversal.
    ///
    /// This will fail if there were unused challenges or masked witnesses.
    pub(crate) fn into_parts(self) -> Result<(F128b, F128b)> {
        if self.assigned_witness_count != self.masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Proof contained more masked witnesses than it needed! Had {}, used {}",
                self.masked_witnesses.len(),
                self.assigned_witness_count
            );
        }
        Ok((self.aggregate, self.aggregate_assert_zero))
    }

    /// Run `circuit` using [`VerifierTraverser`].
    pub(crate) fn execute<C: Circuit<Self, Input = ()>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(self, (), channel)?;
            Ok(())
        })
    }
}

/// An [`F128b`] element representing a VOLE tag.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire(F128b);

impl HasModulus for Wire {
    fn modulus(&self) -> u16 {
        2
    }
}

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl FieldBackend<F2> for VerifierTraverser {
    type Wire = F128b;

    fn input_public(&mut self) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `input_public`")
    }

    fn input_private(&mut self) -> Result<Self::Wire> {
        self.next_masked_witness()
    }

    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        Ok(lhs + rhs)
    }

    fn addc(&mut self, lhs: &Self::Wire, rhs: F2) -> Result<Self::Wire> {
        // Compute the correct masked witness for the output wire
        let t = if rhs == F2::ZERO {
            F128b::ZERO
        } else {
            F128b::ONE
        };
        Ok(lhs - t * self.verifier_key)
    }

    fn mul(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> Result<Self::Wire> {
        // Assign the next masked witness to the destination wire
        let res = self.next_masked_witness()?;
        let challenge = self.chi_challenge.next();

        // Compute the contibution to the aggregate: ci​(Δ) = q_left * ​q_right ​− q_dst * ​Δ
        let eval = lhs * rhs - (res * self.verifier_key);

        self.aggregate += challenge * eval;

        Ok(res)
    }

    fn mulc(&mut self, _: &Self::Wire, _: F2) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `mulc`")
    }

    fn assert_zero(&mut self, arg: &Self::Wire) -> Result<()> {
        let challenge = self.chi_challenge.next();

        self.aggregate_assert_zero += challenge * arg;
        Ok(())
    }
}

impl Fancy for VerifierTraverser {
    type Item = Wire;
}

impl FancyBinaryConstant for VerifierTraverser {
    fn constant(&mut self, constant: bool) -> Self::Item {
        let value = if constant { F128b::ONE } else { F128b::ZERO };
        Wire(-value * self.verifier_key)
    }
}

impl FancyEncode for VerifierTraverser {
    fn encode_many(&mut self, _: &[u16], _: &[u16], _: &mut Channel) -> Result<Vec<Self::Item>> {
        bail!(
            ErrorKind::OtherError,
            "Invalid input: VOLE-in-the-head verifier does not support encode"
        )
    }

    fn receive_many(&mut self, moduli: &[u16], _: &mut Channel) -> Result<Vec<Self::Item>> {
        let mut output = Vec::with_capacity(moduli.len());
        for _ in 0..moduli.len() {
            // Assign a fresh masked witness to the wire
            let res = self.next_masked_witness()?;

            // Private input gates don't define a polynomial that would contribute to the aggregate
            // being computed, so we ignore the challenge
            output.push(Wire(res));
        }
        Ok(output)
    }
}

impl FancyBinary for VerifierTraverser {
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
        Wire(x.0 - F128b::ONE * self.verifier_key)
    }
}

impl FancyZeroKnowledge for VerifierTraverser {
    fn assert_zero(&mut self, value: &Self::Item, _: &mut Channel) -> Result<()> {
        let challenge = self.chi_challenge.next();

        self.aggregate_assert_zero += challenge * value.0;
        Ok(())
    }
}
