#![allow(dead_code)]
use diet_mac_and_cheese::circuit_ir::{GateM, TapeT};
use eyre::{bail, eyre};
use mac_n_cheese_sieve_parser::{
    ConversionSemantics, Identifier, Number, TypeId, TypedWireRange, WireId, WireRange,
};
use std::collections::HashMap;
use swanky_field::PrimeFiniteField;
use swanky_field_binary::F2;

/// A [`ProverPreparer`] allows the prover to prepare for VOLE-in-the-head by evaluating the
/// circuit in the clear and determining the full extended witness.
///
/// The total extended witness includes two types of values:
/// - Private inputs to the circuit (this is the "non-extended" witness)
/// - Outputs of non-linear (multiplication) gates (this is the "extended" part)
///
/// ## Failure modes
/// This type is only designed to be used with a VOLE-in-the-head circuit. Its methods will fail
/// if it visits a circuit where:
/// - there are gates other than `private-input`, `add`, or `mul`
/// - there is more than one type ID used for any gate
/// - any private input to the circuit is not in $`F2`$
#[derive(Debug, Default)]
pub struct ProverPreparer2<I: TapeT, C: Iterator<Item = GateM>> {
    /// Complete map of values on every wire in the circuit.
    wire_values: HashMap<WireId, F2>,

    /// Set of wire values that correspond to elements in the extended witness.
    witness: Vec<F2>,

    /// Number of polynomials that will need challenges.
    challenge_count: usize,

    /// Private input stream, used in circuit evaluation.
    private_inputs: I,

    /// gates
    gates: C,
}

impl<I: TapeT, C: Iterator<Item = GateM>> ProverPreparer2<I, C> {
    ///
    pub fn new(inputs: I, gates: C) -> eyre::Result<Self> {
        Ok(Self {
            wire_values: HashMap::default(),
            witness: Vec::default(),
            challenge_count: 0,
            private_inputs: inputs,
            gates,
        })
    }
}

impl<I: TapeT, C: Iterator<Item = GateM>> ProverPreparer2<I, C> {
    pub(crate) fn count(&self) -> usize {
        self.witness.len()
    }

    /// Save a value in our wire map.
    fn save_wire(&mut self, wid: WireId, value: F2) -> eyre::Result<()> {
        // Assumption: Every wire ID will be assigned to exactly once, so if there's already a
        // value associated with a wire ID, the circuit is malformed.
        if self.wire_values.insert(wid, value).is_some() {
            bail!(
                "Invalid input: assigned to a wire ID {} more than once",
                wid
            );
        }
        Ok(())
    }

    /// Get the witness, wire values, and number of challenges required.
    ///
    /// These values will be empty if the circuit has not yet been traversed.
    pub(crate) fn into_parts(self) -> (Vec<F2>, HashMap<WireId, F2>, usize) {
        (self.witness, self.wire_values, self.challenge_count)
    }
}

impl<I: TapeT, C: Iterator<Item = GateM>> ProverPreparer2<I, C> {
    fn delete(&mut self, _ty: TypeId, _first: WireId, _last: WireId) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `delete` gates");
    }
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        let sum = match (self.wire_values.get(&left), self.wire_values.get(&right)) {
            (Some(l_val), Some(r_val)) => l_val + r_val,
            _ => bail!("Malformed circuit: used a wire that has not yet been defined"),
        };

        self.save_wire(dst, sum)
    }

    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        self.challenge_count += 1;

        let product = match (self.wire_values.get(&left), self.wire_values.get(&right)) {
            (Some(l_val), Some(r_val)) => l_val * r_val,
            _ => bail!("Malformed circuit: used a wire that has not yet been defined"),
        };

        // Save product to the witness and associate it with its wire ID
        self.witness.push(product);
        self.save_wire(dst, product)
    }

    fn addc(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &Number,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `addc` gates");
    }
    fn mulc(
        &mut self,
        _ty: TypeId,
        _dst: WireId,
        _left: WireId,
        _right: &Number,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `mulc` gates");
    }
    fn copy(&mut self, _ty: TypeId, _dst: WireRange, _src: &[WireRange]) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `copy` gates");
    }
    fn constant(&mut self, _ty: TypeId, _dst: WireId, _src: &Number) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `constant` gates");
    }
    fn public_input(&mut self, _ty: TypeId, _dst: WireRange) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `public_input` gates");
    }

    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> eyre::Result<()> {
        // Assumption: There is exactly one type ID for these circuits and it is F2.
        assert_eq!(ty, 0);

        for wid in dst.start..=dst.end {
            // Extract each input from the input stream and check that it's in F2
            let value = self
                .private_inputs
                .pop()
                .ok_or_else(|| eyre!("Invalid input: Private input was not in F2"))?;
            let f2 = F2::try_from_int(value).unwrap();

            // Save private input to the witness and associate it with its wire ID
            self.witness.push(f2);
            self.save_wire(wid, f2)?;
        }
        Ok(())
    }

    fn assert_zero(&mut self, _ty: TypeId, _src: WireId) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `assert_zero` gates");
    }
    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `convert` gates");
    }
    fn call(
        &mut self,
        _dst: &[WireRange],
        _name: Identifier,
        _args: &[WireRange],
    ) -> eyre::Result<()> {
        bail!("Invalid input: VOLE-in-the-head does not support `call` gates");
    }

    ///
    pub fn execute_gate(&mut self, gate: GateM) -> eyre::Result<()> {
        use GateM::*;
        match gate {
            Add(ty, dst, left, right) => {
                self.add(ty, dst, left, right)?;
            }
            Mul(ty, dst, left, right) => {
                self.mul(ty, dst, left, right)?;
            }
            _ => {
                panic!("missing cases");
            }
        }
        Ok(())
    }

    ///
    pub fn compute(&mut self) -> eyre::Result<()> {
        loop {
            if let Some(gate) = self.gates.next() {
                self.execute_gate(gate)?
            } else {
                break;
            }
        }
        Ok(())
    }
}
