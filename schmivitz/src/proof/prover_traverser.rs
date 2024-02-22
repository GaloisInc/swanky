use std::collections::HashMap;

use eyre::{bail, eyre, Result};
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, PluginBinding, RelationVisitor,
    TypeId, TypedCount, TypedWireRange, WireId, WireRange,
};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};

use crate::vole::RandomVole;

/// A [`ProverTraverser`] allows the prover to execute the gate-by-gate evaluation portion of the
/// VOLE-in-the-head protocol.
///
/// The primary steps in circuit traversal include assigning VOLEs to each wire and
/// computing the two aggregated values used in the proof.
pub(crate) struct ProverTraverser<Vole> {
    /// Map containing the full set of wire values for the entire circuit.
    ///
    /// Note: For the currently-accepted set of gates, it is actually only necessary for this to
    /// contain the input wires for multiplication gates, but the current structure of the
    /// [`ProverPreparer`](crate::proof::prover_preparer::ProverPreparer) will produce
    /// the full set of wire values.
    wire_values: HashMap<WireId, F2>,
    /// Fiat-Shamir challenges. There should be one for each polynomial (e.g. non-linear gate).
    challenges: Vec<F128b>,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Assignment of VOLE values to specific wires in the circuit.
    ///
    /// This is constructed during circuit traversal; it holds computed output VOLE values for
    /// linear gates and assigned VOLE values (pulled out of `voles`) for non-linear gates.
    assigned_voles: HashMap<WireId, F128b>,
    /// Count of how many of the custom VOLEs have been assigned.
    vole_assignment_count: usize,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_degree_0: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_degree_1: F128b,
}

impl<Vole: RandomVole> ProverTraverser<Vole> {
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

            voles,
            assigned_voles: HashMap::new(),
            vole_assignment_count: 0,

            aggregate_degree_0: F128b::ZERO,
            aggregate_degree_1: F128b::ZERO,
        })
    }

    /// Retrieve the wire value associated with the [`WireId`].
    ///
    /// Fails if the wire value map provided by the caller does not contain the given ID.
    fn wire_value(&self, wid: WireId) -> Result<F2> {
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
    /// VOLE for a linear gate and assigning it via [`Self::save_computed_vole()`].
    fn vole(&self, wid: WireId) -> Result<F128b> {
        self.assigned_voles
            .get(&wid)
            .ok_or_else(|| {
                eyre!(
                    "Internal invariant failed: expected a VOLE correlated to wire ID {}",
                    wid
                )
            })
            .copied()
    }

    /// Associates the given VOLE with the [`WireId`].
    ///
    /// This should be called with the destination [`WireId`] for each linear gate encountered.
    /// The correct `vole` value is determined by the specific gate type; for example, the correct
    /// VOLE for an addition gate is the sum of the VOLEs of the two input wires. This method
    /// does not validate the correctness of the VOLE.
    ///
    /// Fails if the wire ID was already associated with a VOLE.
    fn save_computed_vole(&mut self, wid: WireId, vole: F128b) -> Result<()> {
        match self.assigned_voles.insert(wid, vole) {
            Some(_) => bail!(
                "Something went wrong assigning a VOLE to {}; it was already assigned!",
                wid
            ),
            None => Ok(()),
        }
    }

    /// Assigns an unused VOLE to the wire ID and returns a challenge for the gate.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_vole()`] to
    /// assign a VOLE value to a linear gate.
    ///
    /// Fails if there aren't enough VOLEs or if the [`WireId`] is already assigned to a VOLE.
    fn assign_vole(&mut self, wid: WireId) -> Result<F128b> {
        let next_index = self.vole_assignment_count;
        self.vole_assignment_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.voles.extended_witness_length() || next_index >= self.challenges.len()
        {
            bail!(
                "Bad input: needed at least {} VOLEs, but only got {}",
                next_index,
                self.voles.extended_witness_length()
            )
        }

        self.save_computed_vole(wid, self.voles.vole_mask(next_index)?)?;
        Ok(self.challenges[next_index])
    }

    /// Decomposes into the aggregate components that we constructed during the
    /// full circuit traversal.
    ///
    /// The components that were passed to [`Self::new()`] are returned unchanged.
    pub(crate) fn into_parts(self) -> (F128b, F128b, Vole, Vec<F128b>) {
        (
            self.aggregate_degree_0,
            self.aggregate_degree_1,
            self.voles,
            self.challenges,
        )
    }
}

impl<Vole: RandomVole> FunctionBodyVisitor for ProverTraverser<Vole> {
    fn new(&mut self, __ty: TypeId, _first: WireId, _last: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `new` gates");
    }

    fn delete(&mut self, _ty: TypeId, _first: WireId, _last: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `delete` gates");
    }

    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Compute the correct VOLE for the output wire
        let sum_vole = self.vole(left)? + self.vole(right)?;
        self.save_computed_vole(dst, sum_vole)

        // Linear gates don't contribute to the aggregated values being computed
    }

    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Assign a fresh VOLE to the output wire and get the corresponding challenge
        let challenge = self.assign_vole(dst)?;

        // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let degree_0_coeff = self.vole(left)? * self.vole(right)?;
        let degree_1_coeff = self.wire_value(right)? * self.vole(left)?
            + self.wire_value(left)? * self.vole(right)?
            - self.vole(dst)?;

        self.aggregate_degree_0 += challenge * degree_0_coeff;
        self.aggregate_degree_1 += challenge * degree_1_coeff;

        Ok(())
    }

    fn addc(&mut self, _ty: TypeId, _dst: WireId, _left: WireId, _right: &Number) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `addc` gates");
    }

    fn mulc(&mut self, _ty: TypeId, _dst: WireId, _left: WireId, _right: &Number) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `mulc` gates");
    }

    fn copy(&mut self, _ty: TypeId, _dst: WireRange, _src: &[WireRange]) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `copy` gates");
    }

    fn constant(&mut self, _ty: TypeId, _dst: WireId, _src: &Number) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `constant` gates");
    }

    fn public_input(&mut self, _ty: TypeId, _dst: WireRange) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `public_input` gates");
    }

    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Assign a fresh VOLE to each of the output wires
        for wid in dst.start..=dst.end {
            let _challenge = self.assign_vole(wid)?;
        }

        // Private input gates don't define a polynomial that would contribute to the aggregated
        // coefficients being computed

        Ok(())
    }

    fn assert_zero(&mut self, _ty: TypeId, _src: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `assert_zero` gates");
    }

    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `convert` gates");
    }

    fn call(&mut self, _dst: &[WireRange], _name: Identifier, _args: &[WireRange]) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `call` gates");
    }
}

impl<Vole: RandomVole> RelationVisitor for ProverTraverser<Vole> {
    type FBV<'a> = Self;
    fn define_function<BodyCb>(
        &mut self,
        _name: Identifier,
        _outputs: &[TypedCount],
        _inputs: &[TypedCount],
        _body: BodyCb,
    ) -> Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> Result<()>,
    {
        bail!("Invalid input: VOLE-in-the-head does not support function definition");
    }

    fn define_plugin_function(
        &mut self,
        _name: Identifier,
        _outputs: &[TypedCount],
        _inputs: &[TypedCount],
        _body: PluginBinding,
    ) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support function definition");
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

    use super::ProverTraverser;

    fn dummy_traverser(len: usize) -> ProverTraverser<InsecureVole> {
        let transcript = &mut Transcript::new(b"dummy for tests");
        let rng = &mut thread_rng();

        let (voles, _) = InsecureVole::create(len, transcript, rng);
        let challenges = repeat_with(|| F128b::random(rng)).take(len).collect();
        let wire_ids = repeat_with(|| (rng.gen(), F2::random(rng))).take(len);
        ProverTraverser::new(HashMap::from_iter(wire_ids), challenges, voles).unwrap()
    }

    #[test]
    fn vole_assignment_works_as_expected() -> Result<()> {
        let len = 20;
        let mut traverser = dummy_traverser(len);
        // Assume every gate is non-linear, for fun
        let non_linear_gates = traverser.wire_values.keys().cloned().collect::<Vec<_>>();

        for (expected_idx, gate) in non_linear_gates.into_iter().enumerate() {
            // If the VOLE hasn't been assigned, you can't retrieve it
            assert!(traverser.vole(gate).is_err());

            // Request a VOLE to be assigned to the wire...
            traverser.assign_vole(gate)?;

            // ...and make sure the assignment is in order wrt the VOLE indexes (0, 1, 2...)
            assert_eq!(traverser.vole_assignment_count, expected_idx + 1);

            // Now you can retrieve the VOLE
            assert!(traverser.vole(gate).is_ok());
        }

        // Can't assign more VOLEs than you have
        assert!(traverser.assign_vole(len as u64).is_err());

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
            traverser.save_computed_vole(wid, vole)?;

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
            traverser.save_computed_vole(*wid, vole)?;

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
            assert!(traverser.save_computed_vole(*wid, vole).is_err());
        }

        Ok(())
    }
}
