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
    //
    // Polynomials are passed as a range where the first wire is the most significant coefficient.
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
        // p0_degree (= n in the spec) is the degree of p0, i.e. one less than the number of coefficients in p0
        let p0_degree = input_counts[0].1 - 1;
        let p1_degree = input_counts[1].1 - 1;
        let q_degree = input_counts[2].1 - 1;
        ensure!(
            p1_degree == 1,
            "{}: p1 must be a degree 1 polynomial",
            Self::NAME
        );
        ensure!(
            q_degree == p0_degree + 1,
            "{}: q must be a degree n+1 polynomial, where n is the degree of p0",
            Self::NAME
        );

        let p0_start = 0;
        let p1_start = input_counts[0].1;
        let q_start = input_counts[0].1 + 2;

        let mut gates = vec![];
        if field == std::any::TypeId::of::<F61p>() {
            // TODO: How many times do we test the polynomial? Is there a target security level for all fields?
            // We evaluate the polynomials in a single challenge point.
            let challenge_wire = first_unused_wire_id(output_counts, input_counts);
            gates.push(GateM::Challenge(type_id, challenge_wire));

            // Compute p0(challenge)
            let (p0_eval_wire, next_unused_wire) = eval_poly(
                &mut gates,
                type_id,
                p0_degree,
                p0_start,
                challenge_wire,
                challenge_wire + 1,
            );
            // Compute p1(challenge)
            let (p1_eval_wire, next_unused_wire) = eval_poly(
                &mut gates,
                type_id,
                p1_degree,
                p1_start,
                challenge_wire,
                next_unused_wire,
            );
            // Compute q(challenge)
            let (q_eval_wire, next_unused_wire) = eval_poly(
                &mut gates,
                type_id,
                q_degree,
                q_start,
                challenge_wire,
                next_unused_wire,
            );
            // Compute p0(challenge)*p1(challenge)
            let p0_mul_p1 = next_unused_wire;
            gates.push(GateM::Mul(type_id, p0_mul_p1, p0_eval_wire, p1_eval_wire));
            // Compute p0(challenge)*p1(challenge)-q(challenge)
            let difference = p0_mul_p1 + 1;
            gates.push(GateM::Sub(type_id, difference, p0_mul_p1, q_eval_wire));
            // Constrain the result to 0
            gates.push(GateM::AssertZero(type_id, difference));
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
    //
    // Polynomials are passed as a range where the first wire is the most significant coefficient.
    fn shift_eq_body(
        _params: &[PluginTypeArg],
        _output_counts: &[(TypeId, WireCount)],
        _input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
    ) -> Result<GatesBody> {
        todo!("shift_eq_body")
    }
}

// Compute p(x), return the wire containing p(x) and the next unused wire.
fn eval_poly(
    gates: &mut Vec<GateM>,
    type_id: u8,
    degree: u64,
    p_start: u64, // the wire containing the first (most significant) coefficient of p
    x: u64,       //
    first_unused_wire: u64,
) -> (u64, u64) {
    // The accumulator is initially the most significant coefficient.
    let mut acc_wire = p_start;
    for i in 0..degree {
        // We use two wires in each iteration.
        let x_mul_acc = first_unused_wire + (i * 2);
        // Compute x * accumulator
        gates.push(GateM::Mul(type_id, x_mul_acc, x, acc_wire));

        // Add the next coefficient and update accumulator wire
        acc_wire = x_mul_acc + 1;
        gates.push(GateM::Add(type_id, acc_wire, x_mul_acc, p_start + i + 1));
    }
    (acc_wire, first_unused_wire + 2 * degree)
}

#[cfg(test)]
mod tests {
    use std::ops::MulAssign;

    use super::GaloisPolyV0;
    use crate::{
        backend_multifield::tests::{test_circuit, F61P_VEC},
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        plugins::Plugin,
    };
    use rand::Rng;
    use scuttlebutt::{
        field::{polynomial::Polynomial, F61p, FiniteField},
        ring::FiniteRing,
        serialization::CanonicalSerialize,
        AesRng,
    };

    fn convert_poly<F: FiniteField>(p: Polynomial<F>) -> Vec<Vec<u8>> {
        let mut coeffs = p.coefficients;
        coeffs.reverse();
        coeffs.push(p.constant);
        coeffs.into_iter().map(|c| c.to_bytes().to_vec()).collect()
    }

    fn get_product_triple<R: Rng, F: FiniteField>(
        rng: &mut R,
        n: usize,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let p0: Polynomial<F> = Polynomial::random(rng, n);
        let p1: Polynomial<F> = Polynomial::random(rng, 1);
        let mut q = p0.clone();
        q.mul_assign(&p1);

        (convert_poly(p0), convert_poly(p1), convert_poly(q))
    }

    #[test]
    fn test_prod_eq_n0() {
        // Test correct triple verifies
        test_prod_eq_with_n(0, true);
        // Test random triple fails
        test_prod_eq_with_n(0, false)
    }

    #[test]
    fn test_prod_eq_n1() {
        // Test correct triple verifies
        test_prod_eq_with_n(1, true);
        // Test random triple fails
        test_prod_eq_with_n(1, false);
    }

    #[test]
    fn test_prod_eq_n10() {
        // Test correct triple verifies
        test_prod_eq_with_n(10, true);
        // Test random triple fails
        test_prod_eq_with_n(10, false);
    }

    fn test_prod_eq_with_n(degree: u64, should_verify: bool) {
        let p0_size = degree + 1;
        let p1_size = 2;
        let q_size = degree + 2;
        let wire_count = p0_size + p1_size + q_size;

        let fields = vec![F61P_VEC.to_vec()];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "galois_poly_v0".into();
        let func = FuncDecl::new_plugin(
            name.clone(),
            42,
            vec![],
            vec![(0, p0_size), (0, p1_size), (0, q_size)],
            GaloisPolyV0::NAME.into(),
            "prod_eq".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);

        let mut gates = vec![GateM::New(0, 0, wire_count)];
        // Add witness gates for p0
        for i in 0..p0_size {
            gates.push(GateM::Witness(0, i))
        }
        // Add witness gates for p1
        for i in p0_size..p0_size + p1_size {
            gates.push(GateM::Witness(0, i))
        }
        // Add instance gates for q
        for i in p0_size + p1_size..wire_count {
            gates.push(GateM::Instance(0, i))
        }
        gates.push(GateM::Call(Box::new((
            name.clone(),
            vec![],
            vec![
                (0, p0_size - 1),
                (p0_size, p0_size + p1_size - 1),
                (p0_size + p1_size, wire_count - 1),
            ],
        ))));

        let mut rng = AesRng::new();

        let (mut p0, mut p1, q) = get_product_triple::<_, F61p>(&mut rng, degree as usize);
        p0.append(&mut p1);
        let witnesses = if should_verify {
            vec![p0]
        } else {
            vec![(0..p0_size + p1_size)
                .map(|_| F61p::random(&mut rng).to_bytes().to_vec())
                .collect()]
        };
        let instances = vec![q];

        let result = test_circuit(fields, fun_store, gates, instances, witnesses);
        if should_verify {
            assert!(result.is_ok())
        } else {
            assert!(result.is_err())
        }
    }
}
