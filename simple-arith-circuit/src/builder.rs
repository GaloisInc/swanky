//! This module implements functions for building / extending circuits.

use crate::{Circuit, Op};
use scuttlebutt::field::{FiniteField, F2};
use scuttlebutt::ring::FiniteRing;

/// Adds an equality check to `circuit` such that the new circuit
/// outputs zero if the output of the old circuit is `value`.
///
/// # Errors
///
/// Errors out if the circuit does not have exactly one output wire.
pub fn add_equality_check<F: FiniteField>(mut circuit: Circuit<F>, value: F) -> Circuit<F> {
    assert_eq!(circuit.noutputs(), 1);
    circuit.push(Op::Constant(value));
    circuit.push(Op::Sub(circuit.nwires() - 2, circuit.nwires() - 1));
    circuit
}

/// Adds an equality check to binary `circuit` such that the new circuit
/// outputs zero if the outputs of the old circuit match `values`.
///
/// # Errors
///
/// Errors out if the length of `values` does not equal the number of outputs of
/// the circuit.
pub fn add_binary_equality_check(mut circuit: Circuit<F2>, values: &[F2]) -> Circuit<F2> {
    assert_eq!(values.len(), circuit.noutputs());
    let output_range = circuit.len() - circuit.noutputs()..circuit.len();
    // Add constants for all the equality check values.
    for value in values {
        circuit.push(Op::Constant(*value));
    }
    let value_range = circuit.len() - values.len()..circuit.len();
    // Add a one for negating.
    let one = circuit.push(Op::Constant(F2::ONE));
    let mut results = Vec::with_capacity(values.len());
    // Subtract the equality check values from the circuit output values and negate them.
    for (output, value) in output_range.zip(value_range) {
        let wire = circuit.push(Op::Sub(
            circuit.ninputs() + output,
            circuit.ninputs() + value,
        ));
        let wire = circuit.push(Op::Add(circuit.ninputs() + wire, circuit.ninputs() + one));
        results.push(wire);
    }
    // Now AND all the resulting wires.
    // TODO: This would be more efficient as a tree.
    let wire = results.iter().fold(circuit.len() - 1, |wire, result| {
        circuit.push(Op::Mul(
            circuit.ninputs() + wire,
            circuit.ninputs() + *result,
        ))
    });
    // Finally, flip the bit so zero means equal.
    circuit.push(Op::Add(circuit.ninputs() + wire, circuit.ninputs() + one));
    // We now have one output.
    circuit.noutputs = 1;
    circuit
}
