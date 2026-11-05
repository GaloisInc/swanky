use fancy_traits::{Circuit, Fancy, FancyBinary, FancyConstant, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_sieve_ir_api::{CircuitResult, FieldBackend, HigherDegreeBackend};

/// Values produced by a completed prover preparation.
pub(crate) struct ProverPreparerParts {
    /// Extended witness values collected during traversal.
    pub(crate) witness: Vec<F2>,
    /// Number of Fiat-Shamir challenges required by the circuit.
    pub(crate) challenge_count: usize,
    /// Maximum degree among the circuit's higher-degree constraints.
    pub(crate) max_higher_degree: usize,
}

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
/// - there are gates other than `private-input`, `add`, `addc`, or `mul`
/// - there is more than one type ID used for any gate
/// - any private input to the circuit is not in [`F2`]
#[derive(Debug)]
pub struct ProverPreparer<'a> {
    /// Private circuit inputs.
    private_input: &'a [F2],

    /// Current position for the next witness value.
    priv_input_pos: u64,

    /// Set of wire values that correspond to elements in the extended witness.
    witness: Vec<F2>,

    /// Number of polynomials that will need challenges.
    challenge_count: usize,

    /// Maximum degree among the higher-degree constraint polynomials.
    max_higher_degree: usize,
}

impl<'a> ProverPreparer<'a> {
    /// Create a new [`ProverPreparer`] using the provided private input and an
    /// optional witness size.
    pub(crate) fn new(
        private_input: &'a [F2],
        witness_size: Option<usize>,
    ) -> swanky_error::Result<Self> {
        Ok(Self {
            private_input,
            priv_input_pos: 0,
            witness: Vec::with_capacity(witness_size.unwrap_or(0)),
            challenge_count: 0,
            max_higher_degree: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.witness.len()
    }

    /// Get the maximum degree among the higher-degree constraint polynomials seen during
    /// traversal (0 if there were none).
    #[cfg(test)]
    pub(crate) fn max_higher_degree(&self) -> usize {
        self.max_higher_degree
    }

    /// Decompose the preparer into the values computed during circuit traversal.
    ///
    /// The values will be null if the circuit has not been traversed.
    pub(crate) fn into_parts(self) -> ProverPreparerParts {
        ProverPreparerParts {
            witness: self.witness,
            challenge_count: self.challenge_count,
            max_higher_degree: self.max_higher_degree,
        }
    }

    /// Run `circuit` using [`ProverPreparer`].
    pub(crate) fn execute<C: Circuit<Self, Input = ()>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            circuit.execute(self, (), channel)?;
            Ok(())
        })
    }
}

/// Wrapper around the [`F2`] type to make it compatible with [`Fancy::Item`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire(F2);

// TODO: Remove! This API has been replaced with the `fancy-traits::Circuit`
// API. We're keeping this around for now for backwards compatibility.
impl<'a> FieldBackend<F2> for ProverPreparer<'a> {
    type Wire = F2;

    fn input_public(&mut self) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `input_public`")
    }

    fn input_private(&mut self) -> Result<Self::Wire> {
        let f2 = self.private_input[self.priv_input_pos as usize];
        self.priv_input_pos += 1;

        // TODO: Can we push all of the input witnesses up front?
        self.witness.push(f2);

        Ok(f2)
    }

    fn add(&mut self, left: &Self::Wire, right: &Self::Wire) -> Result<Self::Wire> {
        let sum = left + right;

        Ok(sum)
    }

    fn addc(&mut self, left: &Self::Wire, right: F2) -> Result<Self::Wire> {
        let sum = left + right;

        Ok(sum)
    }

    fn mul(&mut self, left: &Self::Wire, right: &Self::Wire) -> Result<Self::Wire> {
        self.challenge_count += 1;

        let product = left * right;
        self.witness.push(product);
        Ok(product)
    }

    fn mulc(&mut self, _: &Self::Wire, _: F2) -> Result<Self::Wire> {
        unimplemented!("VOLE-in-the-head does not support `mulc`")
    }

    fn assert_zero(&mut self, _: &Self::Wire) -> Result<()> {
        self.challenge_count += 1;
        Ok(())
    }
}

impl<'a> Fancy for ProverPreparer<'a> {
    type Item = Wire;
}

impl<'a> FancyConstant<F2> for ProverPreparer<'a> {
    fn constant(&mut self, constant: F2) -> Self::Item {
        Wire(constant)
    }
}

impl<'a> FancyBinary for ProverPreparer<'a> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        Wire(x.0 + y.0)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        self.challenge_count += 1;

        let z = x.0 * y.0;

        // Save product to the witness.
        self.witness.push(z);

        Ok(Wire(z))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        Wire(x.0 + F2::ONE)
    }
}

impl<'a> FancyZeroKnowledge<F2> for ProverPreparer<'a> {
    fn witness(&mut self, _: &mut Channel) -> Result<Self::Item> {
        let f2 = self.private_input[self.priv_input_pos as usize];
        self.priv_input_pos += 1;

        // TODO: Can we push all of the input witnesses up front?
        self.witness.push(f2);
        Ok(Wire(f2))
    }

    fn assert_zero(&mut self, _: &Self::Item, _: &mut Channel) -> Result<()> {
        self.challenge_count += 1;
        Ok(())
    }
}

impl<'a, FE> HigherDegreeBackend<F2, FE> for ProverPreparer<'a> {
    /// The degree of the commitment polynomial that the
    /// [`ProverTraverser`](crate::proof::prover_traverser::ProverTraverser) will build for the
    /// wire.
    ///
    /// The degree rules mirror [`crate::higher_degree_commitment::CommitmentPolynomialProver`]: input
    /// wires have degree 1, addition aligns to the larger degree, and multiplication sums the
    /// degrees.
    type HigherDegreeWire = usize;

    fn h_add(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(*lhs.max(rhs))
    }

    fn h_addc(&self, lhs: &Self::HigherDegreeWire, _: F2) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(*lhs)
    }

    fn h_mul(
        &self,
        lhs: &Self::HigherDegreeWire,
        rhs: &Self::HigherDegreeWire,
    ) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(lhs + rhs)
    }

    fn h_mulc(&self, lhs: &Self::HigherDegreeWire, _: F2) -> CircuitResult<Self::HigherDegreeWire> {
        Ok(*lhs)
    }

    fn assert_zero_higher_degree<const INPUT_LEN: usize>(
        &mut self,
        _: &[Self::Wire; INPUT_LEN],
        f: impl Fn(&Self, [Self::HigherDegreeWire; INPUT_LEN]) -> CircuitResult<Self::HigherDegreeWire>,
    ) -> CircuitResult<()> {
        // Each input wire starts at degree one during polynomial traversal.
        let degree = f(self, [1; INPUT_LEN])?;
        self.challenge_count += 1;
        self.max_higher_degree = self.max_higher_degree.max(degree);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::CircuitIngestor;
    use crate::proof::{
        Circuit,
        prover_preparer::{ProverPreparer, ProverPreparerParts},
    };
    use rand::rng;
    use std::io::Cursor;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F2, F128b};
    use swanky_sieve_ir_api::HigherDegreeBackend;
    use swanky_sieve_ir_parser::text_parser::RelationReader;

    /// Take a string description of a circuit and parse it.
    fn load_circuit(circuit: &str) -> swanky_error::Result<Circuit> {
        let rng = &mut rng();
        // Generate a private input vector with 100 random inputs
        let random_private_inputs: Vec<F2> = (0..100).map(|_| F2::random(rng)).collect();

        let cursor = &mut Cursor::new(circuit.as_bytes());
        let reader = RelationReader::new(cursor)?;
        let mut circ = CircuitIngestor::new_prover(random_private_inputs)?;
        reader.read(&mut circ)?;

        let circuit_loaded = circ.into_circuit();
        Ok(circuit_loaded)
    }

    fn prepare_circuit<'a>(
        circuit_loaded: &'a Circuit,
    ) -> swanky_error::Result<ProverPreparer<'a>> {
        let (circuit, private_input, max_wire_id) = circuit_loaded.to_interpreter();

        let mut counter: ProverPreparer =
            ProverPreparer::new(private_input, Some(max_wire_id as usize))?;
        counter.execute(&circuit)?;
        Ok(counter)
    }

    #[test]
    fn private_inputs_count_correctly() -> swanky_error::Result<()> {
        let private_input_only = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @private(0);
            @end ";
        let circuit = load_circuit(private_input_only)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 3);

        let private_input_range = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 ... $3 <- @private(0);
            @end";
        let circuit = load_circuit(private_input_range)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 4);
        Ok(())
    }

    #[test]
    fn multiplication_gates_count_correctly() -> swanky_error::Result<()> {
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
            @end ";
        let circuit = load_circuit(one_mul)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let circuit = load_circuit(many_mul)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }

    #[test]
    fn add_gates_are_not_counted_in_extended_witness() -> swanky_error::Result<()> {
        // These are the same circuits as in `multiplication_gates_count_correctly`, but with an
        // extra `@add` thrown in.
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let circuit = load_circuit(one_mul)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $7 <- @add(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let circuit = load_circuit(many_mul)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }

    // NOTE: breaking down the test with this helper to avoid having to qualify
    // every function called from HigherDegreeBackend.
    fn higher_degree_operations_compute_correct_degrees_helper(
        preparer: &impl HigherDegreeBackend<F2, F128b, HigherDegreeWire = usize>,
    ) {
        let x = 3;
        let y = 2;

        // Addition aligns to the larger degree, multiplication sums the degrees, and constant
        // operations leave the degree unchanged.
        assert_eq!(preparer.h_add(&x, &y).unwrap(), 3);
        assert_eq!(preparer.h_mul(&x, &y).unwrap(), 5);
        assert_eq!(preparer.h_addc(&y, F2::ONE).unwrap(), 2);
        assert_eq!(preparer.h_mulc(&y, F2::ZERO).unwrap(), 2);
    }

    #[test]
    fn higher_degree_operations_compute_correct_degrees() {
        let private_input: Vec<F2> = Vec::new();
        let preparer = ProverPreparer::new(&private_input, None).unwrap();

        higher_degree_operations_compute_correct_degrees_helper(&preparer);
    }

    fn add_degree_four_constraint(
        preparer: &mut impl HigherDegreeBackend<F2, F128b, Wire = F2, HigherDegreeWire = usize>,
    ) -> swanky_error::Result<()> {
        let wires = [F2::ONE, F2::ONE, F2::ZERO, F2::ONE];

        // x0 * x1 * x2 * x3, a degree-4 constraint.
        preparer.assert_zero_higher_degree(&wires, |b, x| {
            let x01 = b.h_mul(&x[0], &x[1])?;
            let x23 = b.h_mul(&x[2], &x[3])?;
            b.h_mul(&x01, &x23)
        })?;

        Ok(())
    }

    fn add_degree_two_constraint(
        preparer: &mut impl HigherDegreeBackend<F2, F128b, Wire = F2, HigherDegreeWire = usize>,
    ) -> swanky_error::Result<()> {
        let wires = [F2::ONE, F2::ONE, F2::ZERO, F2::ONE];

        // x0 * x1 + x2 * x3, a degree-2 constraint.
        preparer.assert_zero_higher_degree(&wires, |b, x| {
            let x01 = b.h_mul(&x[0], &x[1])?;
            let x23 = b.h_mul(&x[2], &x[3])?;
            b.h_add(&x01, &x23)
        })?;

        Ok(())
    }

    #[test]
    fn higher_degree_constraints_track_max_degree() -> swanky_error::Result<()> {
        let private_input: Vec<F2> = Vec::new();
        let mut preparer = ProverPreparer::new(&private_input, None)?;

        assert_eq!(preparer.max_higher_degree(), 0);

        add_degree_four_constraint(&mut preparer)?;
        assert_eq!(preparer.max_higher_degree(), 4);

        // A lower-degree constraint does not lower the maximum.
        add_degree_two_constraint(&mut preparer)?;
        assert_eq!(preparer.max_higher_degree(), 4);

        let ProverPreparerParts {
            witness,
            challenge_count,
            max_higher_degree,
        } = preparer.into_parts();

        assert!(witness.is_empty());
        assert_eq!(challenge_count, 2);
        assert_eq!(max_higher_degree, 4);

        Ok(())
    }

    #[test]
    fn mul_gates_eval_correctly() -> swanky_error::Result<()> {
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @mul(0: $0, $1);
            @end ";

        // This evaluates on a random input; over time we'll check them all
        let circuit = load_circuit(one_mul)?;
        let counter = prepare_circuit(&circuit)?;
        assert_eq!(
            counter.witness.first().unwrap() * counter.witness.get(1).unwrap(),
            *counter.witness.get(2).unwrap()
        );

        Ok(())
    }
}
