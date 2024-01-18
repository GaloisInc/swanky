use std::{collections::HashMap, iter::zip};

use eyre::{bail, eyre, Result};
use mac_n_cheese_sieve_parser::{FunctionBodyVisitor, WireId};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};

use crate::vole::RandomVole;

pub(crate) struct CircuitTraverser<Vole> {
    /// Map containing, at a minimum, the wire values for the entire extended witness
    wire_values: HashMap<WireId, F2>,
    /// Fiat-Shamir challenges. There should be one for each extended witness value.
    challenges: Vec<F128b>,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Computed VOLE values. This is aggregated during circuit traversal to compute the output
    /// value for linear gates.
    computed_voles: HashMap<WireId, F128b>,
    /// Map from wire IDs in the circuit to VOLE indexes, used to correctly index into `voles`
    /// and `challenges`.
    vole_assignment: HashMap<WireId, usize>,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    aggregate_a: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    aggregate_b: F128b,
}

impl<Vole: RandomVole> CircuitTraverser<Vole> {
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `wire_values` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must be exactly the length of the extended witness, according to the [`Vole`];
    /// - The [`Vole::extended_witness_count()`] must be large enough to have a VOLE corresponding
    ///   to every gate in the extended witness.
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
                "Bad input: Length of challenges ({}), extended witness ({}), and VOLEs ({}) did not match",
                challenges.len(),
                wire_values.len(),
                voles.extended_witness_length(),
            );
        }

        // Assign each VOLE to a wire ID corresponding to an item in the extended witness
        let mut witness_wids = wire_values.keys().copied().collect::<Vec<_>>();
        witness_wids.sort();
        let assigned_voles = HashMap::<WireId, usize>::from_iter(zip(
            witness_wids,
            (1..=voles.extended_witness_length()),
        ));

        Ok(Self {
            wire_values,
            challenges,

            voles,
            computed_voles: HashMap::new(),
            vole_assignment: assigned_voles,

            aggregate_a: F128b::ZERO,
            aggregate_b: F128b::ZERO,
        })
    }

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

    fn save_vole(&mut self, wid: WireId, vole: F128b) -> Result<()> {
        match (
            self.computed_voles.insert(wid, vole),
            self.vole_assignment.get(&wid),
        ) {
            // This wire ID should not have any existing VOLEs assigned to it
            (None, None) => Ok(()),
            _ => bail!(
                "Internal invariant failed: Tried to save a computed VOLE, but there is 
                already a VOLE for the wire ID {}",
                wid
            ),
        }
    }

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

        // Linear gates don't contribute to the aggregated values being computed

        // Compute and save the VOLE value for the output wire
        let sum_vole = self.vole(left)? + self.vole(right)?;
        self.save_vole(dst, sum_vole)
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

        // Compute coefficient values `A_i0` and `A_i1` (respectively). These are derived from the
        // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
        let coefficient_a = self.vole(left)? * self.vole(right)?;
        let coefficient_b = self.witness(right)? * self.vole(left)?
            + self.witness(left)? * self.vole(right)?
            - self.vole(dst)?;

        let challenge = self.challenge(dst)?;

        self.aggregate_a += challenge * coefficient_a;
        self.aggregate_b += challenge * coefficient_b;

        // Non-linear gates don't contribute to any computed VOLE values

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
        _dst: mac_n_cheese_sieve_parser::WireRange,
    ) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // I think that input gates don't contribute to the aggregated values being computed
        // because there isn't any constraint being enforced.

        // Private input gates don't contribute to any computed VOLE values; they already should
        // have one assigned to them.

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
