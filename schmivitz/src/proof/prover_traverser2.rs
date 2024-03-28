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
pub struct ProverTraverser2<Vole> {
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
    /// Count of how many of the challenges have been assigned to polynomials (non-linear gates).
    challenge_count: usize,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_degree_0: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_degree_1: F128b,
}

impl<Vole: RandomVole> ProverTraverser2<Vole> {
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `wire_values` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must correspond to the number of polynomials. In this setting, that must
    ///   be no greater than the length of the extended witness (as defined by the [`RandomVole`]);
    /// - The [`RandomVole::extended_witness_length()`] must be large enough to have a VOLE
    ///   corresponding to every gate in the extended witness.
    #[allow(unused)]
    pub fn new(
        wire_values: HashMap<WireId, F2>,
        challenges: Vec<F128b>,
        voles: Vole,
    ) -> Result<Self> {
        if wire_values.len() < challenges.len()
            || voles.extended_witness_length() < challenges.len()
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
            challenge_count: 0,

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

    /// Assigns an unused VOLE to the wire ID.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_vole()`] to
    /// assign a VOLE value to a linear gate.
    ///
    /// Fails if there aren't enough VOLEs or if the [`WireId`] is already assigned to a VOLE.
    fn assign_vole(&mut self, wid: WireId) -> Result<()> {
        let next_index = self.vole_assignment_count;
        self.vole_assignment_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.voles.extended_witness_length() {
            bail!(
                "Bad input: needed at least {} VOLEs, but only got {}",
                self.vole_assignment_count,
                self.voles.extended_witness_length()
            )
        }

        self.save_computed_vole(wid, self.voles.vole_mask(next_index)?)
    }

    /// Retrieves the next unused challenge.
    ///
    /// Fails if there aren't enough challenges.
    fn next_challenge(&mut self) -> Result<F128b> {
        let next_index = self.challenge_count;
        self.challenge_count += 1;
        if next_index >= self.challenges.len() {
            bail!(
                "Bad input: needed at least {} challenges, but only got {}",
                self.challenge_count,
                self.challenges.len()
            )
        }
        Ok(self.challenges[next_index])
    }

    /// Decomposes into the aggregate components that we constructed during the
    /// full circuit traversal.
    ///
    /// The components that were passed to [`Self::new()`] are returned unchanged.
    ///
    /// This will fail if there were unused challenges or VOLEs.
    pub(crate) fn into_parts(self) -> Result<(F128b, F128b, Vole, Vec<F128b>)> {
        if self.challenge_count != self.challenges.len() {
            bail!(
                "Traversal contained more challenges than it needed! Had {}, used {}",
                self.challenges.len(),
                self.challenge_count
            );
        }
        if self.vole_assignment_count != self.voles.extended_witness_length() {
            bail!(
                "Traversal contained more VOLEs than it needed! Had {}, used {}",
                self.voles.extended_witness_length(),
                self.vole_assignment_count
            );
        }
        Ok((
            self.aggregate_degree_0,
            self.aggregate_degree_1,
            self.voles,
            self.challenges,
        ))
    }
}

impl<Vole: RandomVole> ProverTraverser2<Vole> {
    fn new_gate(&mut self, __ty: TypeId, _first: WireId, _last: WireId) -> Result<()> {
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
        self.assign_vole(dst)?;
        let challenge = self.next_challenge()?;

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
            self.assign_vole(wid)?;
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
