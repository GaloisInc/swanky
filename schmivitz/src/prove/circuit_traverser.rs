use std::collections::HashMap;

use eyre::{bail, eyre, Result};
use mac_n_cheese_sieve_parser::{FunctionBodyVisitor, WireId};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};

use crate::vole::RandomVole;

/// Prover-side circuit traversal.
///
/// At a high level, this type can traverse a full circuit, assigning VOLEs to each wire and
/// computing various aggregated values used in the proof.
pub(crate) struct CircuitTraverser<Vole> {
    /// Map containing the full set of wire values for the entire circuit.
    ///
    /// Note: It is actually only necessary for this to contain the input wires for
    /// multiplication gates, but the current structure of the
    /// [`VoleCircuitPreparer`](crate::prove::witness_counter::VoleCircuitPreparer) will produce
    /// the full set.
    wire_values: HashMap<WireId, F2>,
    /// Fiat-Shamir challenges. There should be one for each extended witness value.
    challenges: Vec<F128b>,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Computed VOLE values. This is augmented during circuit traversal with the computed output
    /// VOLE values for linear gates.
    computed_voles: HashMap<WireId, F128b>,
    /// Map from wire IDs in the circuit to VOLE indexes.
    ///
    /// This is used to correctly index into `voles` and `challenges` and is constructed during
    /// circuit traversal.
    vole_assignment: HashMap<WireId, usize>,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_a: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_b: F128b,
}

impl<Vole: RandomVole> CircuitTraverser<Vole> {
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `wire_values` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must be exactly the length of the extended witness, according to the
    ///   [`RandomVole`];
    /// - The [`RandomVole::extended_witness_length()`] must be large enough to have a VOLE
    ///   corresponding to every gate in the extended witness.
    #[allow(unused)]
    pub(crate) fn new(
        wire_values: HashMap<WireId, F2>,
        challenges: Vec<F128b>,
        voles: Vole,
    ) -> Result<Self> {
        if wire_values.len() < challenges.len()
            || voles.extended_witness_length() != challenges.len()
        {
            bail!(
                "Bad input: Length of challenges ({}), extended witness ({}), and VOLEs ({}) did not meet requirements",
                challenges.len(),
                wire_values.len(),
                voles.extended_witness_length(),
            );
        }

        Ok(Self {
            wire_values,
            challenges,

            computed_voles: HashMap::new(),
            vole_assignment: HashMap::with_capacity(voles.extended_witness_length()),
            voles,

            aggregate_a: F128b::ZERO,
            aggregate_b: F128b::ZERO,
        })
    }

    /// Retrieve the witness (wire) value associated with the [`WireId`].
    ///
    /// Fails if the wire value map provided by the caller does not contain the given ID.
    fn witness(&self, wid: WireId) -> Result<F2> {
        self.wire_values
            .get(&wid)
            .ok_or_else(|| {
                eyre!(
                    "Internal invariant failed: expected a witness value for wire ID {}",
                    wid
                )
            })
            .copied()
    }

    /// Retrieve the VOLE value associated with the [`WireId`].
    ///
    /// Fails if the [`WireId`] has not been associated with a VOLE, either by assigning
    /// a new VOLE to a non-linear gate with [`Self::assign_vole()`] or computing the appropriate
    /// VOLE for a linear gate and assigning it via [`Self::save_vole()`].
    fn vole(&self, wid: WireId) -> Result<F128b> {
        // VOLE should be either assigned (for witness gates) or computed (for non-witness gates)
        match (
            self.vole_assignment.get(&wid),
            self.computed_voles.get(&wid),
        ) {
            // If it's assigned, get the VOLE mask
            (Some(vole_id), None) => self.voles.vole_mask(*vole_id),

            // If we computed it at some point, return the computed value
            (None, Some(vole)) => Ok(*vole),

            // If we don't have a VOLE for this wire ID, there's a problem
            (None, None) => bail!(
                "Internal invariant failed: expected a VOLE correlated to wire ID {}",
                wid
            ),

            // There should never be both an assigned _and_ computed version for one wire
            (Some(_), Some(_)) => bail!(
                "Expected exactly one VOLE correlated with wire ID {} but got two",
                wid
            ),
        }
    }

    /// Associates the given VOLE with the [`WireId`].
    ///
    /// This should be called with the destination [`WireId`] for each linear gate encountered.
    /// The correct `vole` value is determined by the specific gate type; for example, the correct
    /// VOLE for an addition gate is the sum of the VOLEs of the two input wires. This method
    /// does not validate the correctness of the VOLE.
    ///
    /// Fails if the wire ID was already associated with a VOLE.
    fn save_vole(&mut self, wid: WireId, vole: F128b) -> Result<()> {
        match (
            self.computed_voles.insert(wid, vole),
            self.vole_assignment.get(&wid),
        ) {
            // This wire ID should not have any existing VOLEs assigned to it
            (None, None) => Ok(()),
            _ => bail!(
                "Something went wrong assigning a VOLE to {}; it was already assigned!",
                wid
            ),
        }
    }

    /// Assigns the wire ID to the next available, unused VOLE.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! See [`Self::save_vole()`] for the correct way to
    /// assign a VOLE value to a linear gate.
    ///
    /// Fails if there aren't enough VOLEs or if the [`WireId`] is already assigned to a VOLE.
    fn assign_vole(&mut self, wid: WireId) -> Result<()> {
        let next_index = self.vole_assignment.len();
        if next_index > self.voles.extended_witness_length() {
            bail!(
                "Bad input: needed at least {} VOLEs, but only got {}",
                next_index,
                self.voles.extended_witness_length()
            )
        }
        match (
            self.vole_assignment.insert(wid, next_index),
            self.computed_voles.get(&wid),
        ) {
            (None, None) => Ok(()),
            _ => bail!(
                "Something went wrong assigning a VOLE to {}; it was already assigned!",
                wid
            ),
        }
    }

    /// Get the challenge associated with the wire ID.
    ///
    /// Fails if we run out of challenges or if the [`WireId`] has not been associated with a VOLE
    /// yet. In general, this method needs to be called for non-linear gates _after_ calling
    /// [`Self::assign_vole()`].
    fn challenge(&self, wid: WireId) -> Result<F128b> {
        let challenge_index = self.vole_assignment.get(&wid).ok_or_else(|| {
            eyre!(
                "Internal invariant failed: expected a VOLE assigned to wire ID {}",
                wid
            )
        })?;
        self.challenges.get(*challenge_index).ok_or_else(||
            eyre!("Internal invariant failed: expected at least {} challenges, but wasn't able to access {}", 
                self.voles.extended_witness_length(), wid))
            .copied()
    }
}

impl<Vole: RandomVole> FunctionBodyVisitor for CircuitTraverser<Vole> {
    fn new(
        &mut self,
        __ty: mac_n_cheese_sieve_parser::TypeId,
        _first: WireId,
        _last: WireId,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `new` gates");
    }

    fn delete(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _first: WireId,
        _last: WireId,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `delete` gates");
    }

    fn add(
        &mut self,
        ty: mac_n_cheese_sieve_parser::TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Compute the correct VOLE for the output wire
        let sum_vole = self.vole(left)? + self.vole(right)?;
        self.save_vole(dst, sum_vole)

        // Linear gates don't contribute to the aggregated values being computed
    }

    fn mul(
        &mut self,
        ty: mac_n_cheese_sieve_parser::TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Assign a fresh VOLE to the output wire
        self.assign_vole(dst)?;

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let coefficient_a = self.vole(left)? * self.vole(right)?;
        let coefficient_b = self.witness(right)? * self.vole(left)?
            + self.witness(left)? * self.vole(right)?
            - self.vole(dst)?;

        let challenge = self.challenge(dst)?;

        self.aggregate_a += challenge * coefficient_a;
        self.aggregate_b += challenge * coefficient_b;

        Ok(())
    }

    fn addc(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &mac_n_cheese_sieve_parser::Number,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `addc` gates");
    }

    fn mulc(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &mac_n_cheese_sieve_parser::Number,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `mulc` gates");
    }

    fn copy(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _dst: mac_n_cheese_sieve_parser::WireRange,
        _src: &[mac_n_cheese_sieve_parser::WireRange],
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `copy` gates");
    }

    fn constant(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _dst: WireId,
        _src: &mac_n_cheese_sieve_parser::Number,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `constant` gates");
    }

    fn public_input(
        &mut self,
        _ty: mac_n_cheese_sieve_parser::TypeId,
        _dst: mac_n_cheese_sieve_parser::WireRange,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `public_input` gates");
    }

    fn private_input(
        &mut self,
        ty: mac_n_cheese_sieve_parser::TypeId,
        dst: mac_n_cheese_sieve_parser::WireRange,
    ) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Assign a fresh VOLE to each of the output wires
        for wid in dst.start..=dst.end {
            self.assign_vole(wid)?;
        }

        // Private input gates don't define a polynomial that would contribute to the aggregated
        // coefficients being computed

        Ok(())
    }

    fn assert_zero(&mut self, _ty: mac_n_cheese_sieve_parser::TypeId, _src: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `assert_zero` gates");
    }

    fn convert(
        &mut self,
        _dst: mac_n_cheese_sieve_parser::TypedWireRange,
        _src: mac_n_cheese_sieve_parser::TypedWireRange,
        _semantics: mac_n_cheese_sieve_parser::ConversionSemantics,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `convert` gates");
    }

    fn call(
        &mut self,
        _dst: &[mac_n_cheese_sieve_parser::WireRange],
        _name: mac_n_cheese_sieve_parser::Identifier,
        _args: &[mac_n_cheese_sieve_parser::WireRange],
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `call` gates");
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, iter::repeat_with};

    use eyre::Result;
    use merlin::Transcript;
    use rand::{thread_rng, Rng};
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F128b, F2};

    use crate::vole::{insecure::InsecureVole, RandomVole};

    use super::CircuitTraverser;

    fn dummy_traverser(len: usize) -> CircuitTraverser<InsecureVole> {
        let transcript = &mut Transcript::new(b"dummy for tests");
        let rng = &mut thread_rng();

        let voles = InsecureVole::create(len, transcript, rng);
        let challenges = repeat_with(|| F128b::random(rng)).take(len).collect();
        let wire_ids = repeat_with(|| (rng.gen(), F2::random(rng))).take(len);
        CircuitTraverser::new(HashMap::from_iter(wire_ids), challenges, voles).unwrap()
    }

    #[test]
    fn vole_assignment_works_as_expected() -> Result<()> {
        let mut traverser = dummy_traverser(4);
        // Assume every gate is non-linear, for fun
        let non_linear_gates = traverser.wire_values.keys().cloned().collect::<Vec<_>>();

        for (expected_idx, gate) in non_linear_gates.into_iter().enumerate() {
            // If the VOLE hasn't been assigned, you can't retrieve it
            assert!(traverser.vole(gate).is_err());

            // Request a VOLE to be assigned to the wire...
            traverser.assign_vole(gate)?;

            // ...and make sure the assignment is in order wrt the VOLE indexes (0, 1, 2...)
            assert_eq!(traverser.vole_assignment.get(&gate).unwrap(), &expected_idx);

            // Now you can retrieve the VOLE
            assert!(traverser.vole(gate).is_ok());
        }

        Ok(())
    }

    #[test]
    fn vole_computation_works_as_expected() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 4;
        let mut traverser = dummy_traverser(len);

        // Assume every gate is linear, for fun
        let linear_gates = traverser.wire_values.keys().cloned().collect::<Vec<_>>();
        for wid in linear_gates {
            // If VOLEs haven't been computed, you can't retrieve them
            assert!(traverser.vole(wid).is_err());

            // "Compute" a VOLE for the gate...
            let vole = F128b::random(rng);
            traverser.save_vole(wid, vole)?;

            // ...and make sure they were assigned as expected
            assert_eq!(traverser.vole(wid)?, vole)
        }

        Ok(())
    }

    #[test]
    fn voles_cannot_be_assigned_and_computed() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 4;
        let mut traverser = dummy_traverser(len);

        // Assume every gate is linear, for fun
        let linear_gates = traverser.wire_values.keys().cloned().collect::<Vec<_>>();
        for wid in &linear_gates[0..2] {
            // If VOLEs haven't been computed/assigned, you can't retrieve them
            assert!(traverser.vole(*wid).is_err());

            // "Compute" a VOLE for the wire
            let vole = F128b::random(rng);
            traverser.save_vole(*wid, vole)?;

            // You shouldn't be able to also assign a VOLE to the wire
            assert!(traverser.assign_vole(*wid).is_err());
        }

        for wid in &linear_gates[2..] {
            // If VOLEs haven't been computed/assigned, you can't retrieve them
            assert!(traverser.vole(*wid).is_err());

            // Assign a new VOLE for the wire
            traverser.assign_vole(*wid)?;

            // You shouldn't be able to also "compute" & assign a VOLE to the wire
            let vole = F128b::random(rng);
            assert!(traverser.save_vole(*wid, vole).is_err());
        }

        Ok(())
    }

    #[test]
    fn challenge_retrieval_works_as_expected() -> Result<()> {
        let len = 5;
        let mut traverser = dummy_traverser(len);

        let wire_ids = traverser.wire_values.keys().cloned().collect::<Vec<_>>();
        for wid in wire_ids {
            // If gates haven't been assigned, you can't get the right challenge
            assert!(traverser.challenge(wid).is_err());

            // Add wire id -> challenge index assignments
            traverser.assign_vole(wid)?;

            // You can get a challenge for every witness
            assert!(traverser.challenge(wid).is_ok());
        }
        Ok(())
    }
}
