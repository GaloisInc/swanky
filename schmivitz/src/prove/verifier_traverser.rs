use std::collections::HashMap;

use eyre::{bail, eyre, Result};
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, PluginBinding, RelationVisitor,
    TypeId, TypedCount, TypedWireRange, WireId, WireRange,
};
use swanky_field::FiniteRing;
use swanky_field_binary::F128b;

/// A [`VerifierTraverser`] allows the verifier to execute the gate-by-gate evaluation portion of
/// the VOLE-in-the-head verification protocol.
///
/// The primary steps in circuit traversal are assigning masked witnesses to each
/// wire (either using provided witnesses from the proof or evaluating expected witnesses for
/// linear gates) and computing the aggregate value used to verify the proof.
pub(crate) struct VerifierTraverser {
    /// Fiat-Shamir challenges. There should be one for each extended witness value.
    challenges: Vec<F128b>,

    /// Verifier's chosen random VOLE key ($`\Delta`$ in the paper).
    verifier_key: F128b,

    /// The masked witness commitments ($`\bf q'`$ in the paper).
    ///
    /// There should be one of these for each extended witness.
    /// Note that these are a function of the random VOLEs correlated with the witness, the
    /// commitment to the witness itself, and the verifier's VOLE key.
    masked_witnesses: Vec<F128b>,

    /// Assignment of masked witnesses to specific wires in the circuit.
    ///
    /// This is constructed during circuit traversal; it holds computed masked witnesses for
    /// linear gates and assigned masked witnesses (pulled out of `masked_witnesses`) for
    /// non-linear gates.
    assigned_masked_witnesses: HashMap<WireId, F128b>,

    /// Count of how many of the provided masked witnesses have been assigned.
    assigned_witness_count: usize,

    /// Partial aggregation of the value $`\tilde c`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $`\sum_{i \in [t]} \chi_i \cdot c_i(\Delta)`$.
    aggregate: F128b,
}

impl VerifierTraverser {
    #[allow(unused)]
    pub(crate) fn new(
        challenges: Vec<F128b>,
        verifier_key: F128b,
        masked_witnesses: Vec<F128b>,
    ) -> Result<Self> {
        if challenges.len() != masked_witnesses.len() {
            bail!(
                "Bad input: There should be the same number of challenges ({}) and masked witnesses ({})",
                challenges.len(),
                masked_witnesses.len(),
            );
        }
        Ok(Self {
            challenges,
            verifier_key,
            masked_witnesses,
            assigned_masked_witnesses: HashMap::new(),
            assigned_witness_count: 0,
            aggregate: F128b::ZERO,
        })
    }

    /// Assign a wire ID to a specific masked witness.
    ///
    /// This should be called with the destination [`WireId`] for each linear gate encountered.
    /// The correct masked witness is determined by the specific gate type; for example, the
    /// correct witness for an addition gate is the sum of the witnesses of the two input wires.
    /// This method does not validate the correctness of the provided witness.
    ///
    /// Fails if the wire ID was already associated with a witness.
    fn save_computed_masked_witness(&mut self, wid: WireId, masked_witness: F128b) -> Result<()> {
        match self.assigned_masked_witnesses.insert(wid, masked_witness) {
            Some(_) => bail!(
                "Something went wrong assigning a masked witness to {}; it was already assigned!",
                wid
            ),
            None => Ok(()),
        }
    }

    /// Assign a wire ID to the next unused masked witness and get the corresponding challenge.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_masked_witness()`] to
    /// assign a specific witness value to a linear gate.
    ///
    /// Fails if there aren't enough unused witnesses or if the [`WireId`] is already assigned to
    /// a masked witness.
    fn assign_masked_witness(&mut self, wid: WireId) -> Result<F128b> {
        let next_index = self.assigned_witness_count;
        self.assigned_witness_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.masked_witnesses.len() || next_index >= self.challenges.len() {
            bail!(
                "Bad input: needed at least {} masked witnesses, but only got {}",
                next_index,
                self.masked_witnesses.len()
            )
        }

        self.save_computed_masked_witness(wid, self.masked_witnesses[next_index])?;
        Ok(self.challenges[next_index])
    }

    /// Retrieve the masked witness associated with the [`WireId`].
    ///
    /// Fails if the [`WireId`] has not been associated with a masked witness, either by assigning
    /// a provided masked witness to a non-linear gate with [`Self::assign_masked_witness()`] or
    /// by computing the appropriate witness for a linear gate and assigning it via
    /// [`Self::save_computed_masked_witness()`].
    fn masked_witness(&self, wid: WireId) -> Result<F128b> {
        self.assigned_masked_witnesses
            .get(&wid)
            .ok_or_else(|| {
                eyre!(
                    "Internal invariant failed: expected a masked witness value for wire ID {}",
                    wid
                )
            })
            .copied()
    }
}

impl FunctionBodyVisitor for VerifierTraverser {
    fn new(&mut self, __ty: TypeId, _first: WireId, _last: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `new` gates");
    }

    fn delete(&mut self, _ty: TypeId, _first: WireId, _last: WireId) -> Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `delete` gates");
    }

    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Compute the correct masked witness for the output wire
        self.save_computed_masked_witness(
            dst,
            self.masked_witness(left)? + self.masked_witness(right)?,
        )

        // Linear gates don't contribute to the aggregate being computed
    }

    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        // Assign the next masked witness to the destination wire
        let challenge = self.assign_masked_witness(dst)?;

        // Compute the contibution to the aggregate: ci​(Δ) = q_left * ​q_right ​− q_dst * ​Δ
        let eval = self.masked_witness(left)? * self.masked_witness(right)?
            - (self.masked_witness(dst)? * self.verifier_key);

        self.aggregate += challenge * eval;

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

        // For each of the output wires:
        for wid in dst.start..=dst.end {
            // Assign a fresh masked witness to the wire
            let _challenge = self.assign_masked_witness(wid)?;

            // Private input gates don't define a polynomial that would contribute to the aggregate
            // being computed, so we ignore the challenge
        }

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

impl RelationVisitor for VerifierTraverser {
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
    use std::{collections::HashSet, iter::repeat_with};

    use eyre::Result;
    use rand::{thread_rng, Rng};
    use swanky_field::FiniteRing;
    use swanky_field_binary::F128b;

    use super::VerifierTraverser;

    fn dummy_traverser(len: usize) -> VerifierTraverser {
        let rng = &mut thread_rng();

        let challenges = repeat_with(|| F128b::random(rng)).take(len).collect();
        let verifier_key = F128b::random(rng);
        let masked_witnesses = repeat_with(|| F128b::random(rng)).take(len).collect();
        VerifierTraverser::new(challenges, verifier_key, masked_witnesses).unwrap()
    }

    #[test]
    fn masked_witness_assignment_works_as_expected() -> Result<()> {
        let len = 20;
        let mut traverser = dummy_traverser(len as usize);

        for wid in 0..len {
            // If the wire ID hasn't been assigned a witness, you can't retrieve it
            assert!(traverser.masked_witness(wid).is_err());

            // Request a masked witness to be assigned to the wire...
            traverser.assign_masked_witness(wid)?;

            // ...and make sure the assignment "counted"
            assert_eq!(traverser.assigned_witness_count as u64, wid + 1);

            // Now you can retrieve the masked witness
            assert!(traverser.masked_witness(wid).is_ok());
        }

        // Can't assign more witnesses than you have
        assert!(traverser.assign_masked_witness(len + 1).is_err());

        Ok(())
    }

    #[test]
    fn masked_witness_computation_works_as_expected() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 25;
        let mut traverser = dummy_traverser(len);

        // Form a random set of unique wire ids (might be smaller than 25 due to repeats)
        let wire_ids: HashSet<_> = repeat_with(|| rng.gen::<u8>() as u64).take(len).collect();

        for wid in wire_ids {
            // If the wire ID doesn't have an associated computed masked witness, retrieval fails
            assert!(traverser.masked_witness(wid).is_err());

            // "Compute" a masked witness for the gate...
            let witness = F128b::random(rng);
            traverser.save_computed_masked_witness(wid, witness)?;

            // ...and make sure they were assigned as expected
            assert_eq!(traverser.masked_witness(wid)?, witness)
        }

        Ok(())
    }

    #[test]
    fn masked_witnesses_cannot_be_assigned_and_computed() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 20;
        let mut traverser = dummy_traverser(len as usize);

        for wid in 0..len / 2 {
            // If masked witnesses haven't been computed/assigned, you can't retrieve them
            assert!(traverser.masked_witness(wid).is_err());

            // "Compute" a witness for the wire
            let witness = F128b::random(rng);
            traverser.save_computed_masked_witness(wid, witness)?;

            // You shouldn't be able to also assign a witness to the wire
            assert!(traverser.assign_masked_witness(wid).is_err());
        }

        for wid in len / 2..len {
            // If masked witnesses haven't been computed/assigned, you can't retrieve them
            assert!(traverser.masked_witness(wid).is_err());

            // Assign a new witness for the wire
            traverser.assign_masked_witness(wid)?;

            // You shouldn't be able to also "compute" & assign a witness to the wire
            let witness = F128b::random(rng);
            assert!(traverser
                .save_computed_masked_witness(wid, witness)
                .is_err());
        }

        Ok(())
    }
}
