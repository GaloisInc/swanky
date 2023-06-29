use super::Plugin;
use crate::circuit_ir::{
    first_unused_wire_id, GateM, GatesBody, TypeId, TypeSpecification, TypeStore, WireCount,
};
use eyre::{ensure, eyre, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use scuttlebutt::field::{F61p, F2};

pub(crate) struct GaloisPolyV0;

impl Plugin for GaloisPolyV0 {
    const NAME: &'static str = "galois_poly_v0";

    fn gates_body(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
    ) -> Result<GatesBody> {
        if operation == "prod_eq" {
            Self::prod_eq_body(params, output_counts, input_counts, type_store)
        } else if operation == "shift_eq" {
            Self::shift_eq_body(params, output_counts, input_counts, type_store)
        } else {
            return Err(eyre!("{}: Invalid operation: {operation}", Self::NAME));
        }
    }
}

impl GaloisPolyV0 {
    // Let F be a finite field.
    // Given
    // a degree-n polynomial p0 (over coefficients in F)
    // a degree-1 polynomial p1 (over coefficients in F)
    // a degree-(n+1) polynomial q (over coefficients in F)
    // Assert whether p0*p1=q
    fn prod_eq_body(
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
    ) -> Result<GatesBody> {
        ensure!(
            params.len() == 0,
            "{}: Invalid number of params (must be zero): {}",
            Self::NAME,
            params.len()
        );
        ensure!(
            output_counts.len() == 0,
            "{}: Output count must be zero",
            Self::NAME
        );
        ensure!(
            input_counts.len() == 3,
            "{}: Input count must be 3",
            Self::NAME
        );
        let type_id = input_counts[0].0;
        ensure!(
            type_id == input_counts[1].0 && type_id == input_counts[2].0,
            "{}: Input type indices must match",
            Self::NAME
        );
        let type_spec = type_store.get(&type_id)?;
        let field = match type_spec {
            TypeSpecification::Field(field) => *field,
            other => {
                return Err(eyre!(
                    "{}: Invalid type specification, must be `Field`: {other:?}",
                    Self::NAME,
                ))
            }
        };
        ensure!(
            input_counts[0].1 != 0, // TODO: Can this even happen?
            "{}: p0 must have at least 1 coefficient",
            Self::NAME
        );
        ensure!(
            input_counts[1].1 == 2,
            "{}: p1 must be a degree 1 polynomial",
            Self::NAME
        );
        // poly_degree (= n in the spec) is the degree of p0, i.e. one more than the number of coefficients in p0
        let p0_degree = input_counts[0].1 - 1;
        let q_degree = p0_degree + 1;
        ensure!(
            input_counts[2].1 == q_degree - 1,
            "{}: q must be a degree n+1 polynomial, where n is the degree of p0",
            Self::NAME
        );
        let mut gates = vec![];
        if field == std::any::TypeId::of::<F61p>() {
            let count = first_unused_wire_id(output_counts, input_counts);
            // TODO: How many times do we test the polynomial? Is there a target security level for all fields?
            // We evaluate the polynomials in a single challenge point.
            let challenge_wire = count;
            gates.push(GateM::Challenge(type_id, challenge_wire));

            // Assuming that a polynomial is passed as a range where the first wire is the most significant coefficient.
            let p0_eval_wire = {
                // Evaluate p0(challenge) using Horner's
                let mut acc_wire = 0;
                for i in 0..p0_degree {
                    // first available wire is after the challenge, and then we use two in each iteration.
                    let x_mul_acc = challenge_wire + (i * 2) + 1;
                    // multiply challenge to accumulator
                    gates.push(GateM::Mul(type_id, x_mul_acc, challenge_wire, acc_wire));
                    // add the next coefficient
                    acc_wire = x_mul_acc + 1;
                    gates.push(GateM::Add(type_id, acc_wire, x_mul_acc, i + 1));
                }
                acc_wire
            };
            // We spent one wire label on the challenge and 2 for each non-constant term of p0.
            let next_free_wire = count + 1 + 2 * p0_degree;
            let p1_eval_wire = {
                let p1_start = input_counts[0].1;
                // the degree of p1 is always 1 so we directly compute a1*challenge and then add a0
                gates.push(GateM::Mul(
                    type_id,
                    next_free_wire,
                    p1_start,
                    challenge_wire,
                ));
                let p1_eval_wire = next_free_wire + 1;
                gates.push(GateM::Add(
                    type_id,
                    p1_eval_wire,
                    p1_start + 1,
                    next_free_wire,
                ));
                p1_eval_wire
            };
            let q_eval_wire = {
                let q_start = input_counts[0].1 + 2;
                let mut acc_wire = q_start;
                for i in 0..q_degree {
                    // as p1 has degree 1 we always use a new wire for its evaluation.
                    let x_mul_acc = p1_eval_wire + (i * 2) + 1;
                    // multiply challenge to accumulator
                    gates.push(GateM::Mul(type_id, x_mul_acc, challenge_wire, acc_wire));
                    // add the next coefficient
                    acc_wire = x_mul_acc + 1;
                    gates.push(GateM::Add(type_id, acc_wire, x_mul_acc, q_start + i + 1));
                }
                acc_wire
            };
            let next_free_wire = p1_eval_wire + 1 + 2 * q_degree;
            // compute the product of p0 and p1 evaluated in the challenge
            gates.push(GateM::Mul(
                type_id,
                next_free_wire,
                p0_eval_wire,
                p1_eval_wire,
            ));
            // subtract the result from q
            gates.push(GateM::Sub(
                type_id,
                next_free_wire + 1,
                next_free_wire,
                q_eval_wire,
            ));
            // Constrain the result to 0
            gates.push(GateM::AssertZero(type_id, next_free_wire + 1));
        } else if field == std::any::TypeId::of::<F2>() {
            // TODO: for F2 (and other small fields) where we want to evaluate in many points, I think it is cheaper to multiply p0 and p1 directly.
            todo!("prod_eq_body")
        } else {
            todo!("Unsupported field: {type_spec:?}.")
        }

        Ok(GatesBody::new(gates))
    }

    // Given
    // a degree-n polynomial p (over coefficients in F)
    // a field element c in F
    // a resulting polynomial q (over coefficients in F)
    // Assert whether p(x-c) = q
    fn shift_eq_body(
        _params: &[PluginTypeArg],
        _output_counts: &[(TypeId, WireCount)],
        _input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
    ) -> Result<GatesBody> {
        todo!("shift_eq_body")
    }
}
