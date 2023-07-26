use super::{Plugin, PluginExecution};
use crate::circuit_ir::{
    first_unused_wire_id, FunStore, GateM, GatesBody, TypeId, TypeSpecification, TypeStore,
    WireCount,
};
use eyre::{ensure, eyre, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use swanky_field_binary::{F128b, F63b, F2};
use swanky_field_f61p::F61p;

pub(crate) struct GaloisPolyV0;

impl Plugin for GaloisPolyV0 {
    const NAME: &'static str = "galois_poly_v0";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
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
    ) -> Result<PluginExecution> {
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
            "{}: Input type IDs must match",
            Self::NAME
        );

        ensure!(
            input_counts[0].1 != 0,
            "{}: p0 must have at least 1 coefficient",
            Self::NAME
        );
        ensure!(
            input_counts[2].1 > 1,
            "{}: q must have at least 2 coefficients",
            Self::NAME
        );
        // p0_degree (= n in the spec) is the degree of p0, i.e. one less than the number of coefficients in p0
        let p0_degree = input_counts[0].1 - 1; // Cannot underflow because we check for length != 0.
        let p1_degree = input_counts[1].1 - 1; // Underflow will be caught in check for degree == 1.
        let q_degree = input_counts[2].1 - 1; // Cannot underflow because we check for length > 1.
        ensure!(
            p1_degree == 1,
            "{}: p1 must be a degree 1 polynomial",
            Self::NAME
        );
        ensure!(
            q_degree == p0_degree + 1, // Cannot overflow as p0_degree was obtained by subtracting 1 from a non-zero value.
            "{}: q must be a degree n+1 polynomial, where n is the degree of p0",
            Self::NAME
        );

        let p0_start = 0;
        let p1_start = input_counts[0].1;
        let q_start = input_counts[0].1 + 2;

        let number_of_challenges = Self::number_of_challenges(q_degree, &type_id, &type_store)?;

        let mut gates = vec![];
        let mut loop_first_wire = first_unused_wire_id(output_counts, input_counts);
        for _ in 0..number_of_challenges {
            // We evaluate the polynomials in a single challenge point.
            let challenge_wire = loop_first_wire;
            gates.push(GateM::Challenge(type_id, challenge_wire));

            // Compute p0(challenge)
            let (p0_eval_wire, next_unused_wire) = Self::eval_poly(
                &mut gates,
                type_id,
                p0_degree,
                p0_start,
                challenge_wire,
                challenge_wire + 1,
            );
            // Compute p1(challenge)
            let (p1_eval_wire, next_unused_wire) = Self::eval_poly(
                &mut gates,
                type_id,
                p1_degree,
                p1_start,
                challenge_wire,
                next_unused_wire,
            );
            // Compute q(challenge)
            let (q_eval_wire, next_unused_wire) = Self::eval_poly(
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
            loop_first_wire = difference + 1;
        }

        Ok(GatesBody::new(gates).into())
    }

    // Given
    // a degree-n polynomial p (over coefficients in F)
    // a field element c in F
    // a resulting polynomial q (over coefficients in F)
    // Assert whether p(x-c) = q
    //
    // Polynomials are passed as a range where the first wire is the most significant coefficient.
    fn shift_eq_body(
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
    ) -> Result<PluginExecution> {
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
            "{}: Input type IDs must match",
            Self::NAME
        );
        ensure!(
            input_counts[0].1 != 0,
            "{}: p must have at least 1 coefficient",
            Self::NAME
        );
        // p_degree (= n in the spec) is the degree of p, i.e. one less than the number of coefficients in p
        let p_degree = input_counts[0].1 - 1;
        let q_degree = input_counts[2].1 - 1;
        ensure!(
            input_counts[1].1 == 1,
            "{}: c must be a constant",
            Self::NAME
        );
        ensure!(
            q_degree == p_degree,
            "{}: q must have the same degree as p",
            Self::NAME
        );

        let p_start = 0;
        let c_wire = input_counts[0].1;
        let q_start = input_counts[0].1 + 1;

        let number_of_challenges = Self::number_of_challenges(q_degree, &type_id, &type_store)?;

        let mut gates = vec![];
        let mut loop_first_wire = first_unused_wire_id(output_counts, input_counts);
        for _ in 0..number_of_challenges {
            let challenge_wire = loop_first_wire;
            gates.push(GateM::Challenge(type_id, challenge_wire));
            let shifted_challenge_wire = challenge_wire + 1;
            gates.push(GateM::Sub(
                type_id,
                shifted_challenge_wire,
                challenge_wire,
                c_wire,
            ));

            // Evaluate p(x-c) and q(x) in the challenge point
            let (p_eval_wire, next_unused_wire) = Self::eval_poly(
                &mut gates,
                type_id,
                p_degree,
                p_start,
                shifted_challenge_wire,
                challenge_wire + 2,
            );
            let (q_eval_wire, next_unused_wire) = Self::eval_poly(
                &mut gates,
                type_id,
                q_degree,
                q_start,
                challenge_wire,
                next_unused_wire,
            );
            // Compute p(x-c) - q(x)
            let difference = next_unused_wire;
            gates.push(GateM::Sub(type_id, difference, p_eval_wire, q_eval_wire));
            // Constraint the result to 0
            gates.push(GateM::AssertZero(type_id, difference));
            loop_first_wire = difference + 1;
        }

        Ok(GatesBody::new(gates).into())
    }

    // Computes p(x).
    // Returns the wire containing p(x) and the next unused wire.
    fn eval_poly(
        gates: &mut Vec<GateM>,
        type_id: u8,
        degree: u64,
        p_start: u64, // the wire containing the first (most significant) coefficient of p
        x: u64,
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

    // TODO: If more than three challenges are needed it is more efficient to check in F^(2^k).
    fn number_of_challenges(
        degree: u64,
        type_id: &TypeId,
        type_store: &TypeStore,
    ) -> Result<usize> {
        let type_spec = type_store.get(&type_id)?;
        let TypeSpecification::Field(field) = type_spec else {
            eyre::bail!("Invalid type specification for inputs; must be `Field`.");
        };

        if degree == 0 {
            return Ok(1);
        };

        // TODO: Should this cover all fields in scuttlebutt?
        // TODO: Is there a better pattern to switch over many fields?
        let field_size = if *field == std::any::TypeId::of::<F61p>() {
            2u64.pow(61) - 1
        } else if *field == std::any::TypeId::of::<F128b>() {
            // With 40 bits security unsound degrees are not representable in u64.
            return Ok(1);
        } else if *field == std::any::TypeId::of::<F63b>() {
            2u64.pow(63)
        } else if *field == std::any::TypeId::of::<F2>() {
            2
        } else {
            todo!("Type id {type_id:?} is not a supported field.")
        };
        if field_size <= degree {
            // TODO: Can be tested in F^(2^k).
            todo!("Degree larger or equal to field size not supported.")
        }
        let bits_of_security = 40;
        // The probability of failure in each test is at most degree/|F|.
        let single_test_failure_probability = degree as f64 / field_size as f64;
        // We want to choose the number of tests such that the probability of failure is at most 2^(-bits_of_security).
        // (degree/|F|)^number_of_challenges <= 2^(-bits_of_security)
        // <=> number_of_challenges >= log_(degree/|F|)(2^(-bits_of_security))
        let number_of_challenges = 2f64
            .powi(-bits_of_security)
            .log(single_test_failure_probability)
            .ceil();
        Ok(number_of_challenges as usize)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::MulAssign;

    use super::GaloisPolyV0;
    use crate::{
        backend_multifield::tests::test_circuit,
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        fields::F61P_MODULUS,
        plugins::Plugin,
    };
    use mac_n_cheese_sieve_parser::Number;
    use rand::Rng;
    use scuttlebutt::{
        field::{polynomial::Polynomial, F61p, PrimeFiniteField},
        ring::FiniteRing,
        AesRng,
    };

    fn convert_poly<F: PrimeFiniteField>(p: Polynomial<F>) -> Vec<Number> {
        let mut coeffs = p.coefficients;
        coeffs.reverse();
        coeffs.push(p.constant);
        coeffs.into_iter().map(|c| c.into_int()).collect()
    }

    fn get_product_triple<R: Rng, F: PrimeFiniteField>(
        rng: &mut R,
        n: usize,
    ) -> (Vec<Number>, Vec<Number>, Vec<Number>) {
        let p0: Polynomial<F> = Polynomial::random(rng, n);
        let p1: Polynomial<F> = Polynomial::random(rng, 1);
        let mut q = p0.clone();
        q.mul_assign(&p1);

        (convert_poly(p0), convert_poly(p1), convert_poly(q))
    }

    fn get_shift_triple<R: Rng, F: PrimeFiniteField>(
        rng: &mut R,
        n: usize,
    ) -> (Vec<Number>, Vec<Number>, Vec<Number>) {
        let p: Polynomial<F> = Polynomial::random(rng, n);
        let c = F::random(rng);

        // Evaluate p in n+1 points to find the coefficients of q by interpolation.
        let mut points = vec![];
        for _ in 0..n + 1 {
            let x = F::random(rng);
            points.push((x, p.eval(x - c)));
        }
        let q = Polynomial::<F>::interpolate(&points);
        assert!(q.degree() == n);

        (convert_poly(p), vec![c.into_int()], convert_poly(q))
    }

    #[test]
    fn test_poly_prod_eq() {
        // Test correct triple verifies
        test_prod_eq_with_degree(0, true);
        test_prod_eq_with_degree(1, true);
        test_prod_eq_with_degree(10, true);
        // Test random triple fails
        test_prod_eq_with_degree(0, false);
        test_prod_eq_with_degree(1, false);
        test_prod_eq_with_degree(10, false);
    }

    fn test_prod_eq_with_degree(degree: u64, should_verify: bool) {
        let p0_size = degree + 1;
        let p1_size = 2;
        let q_size = degree + 2;
        let wire_count = p0_size + p1_size + q_size;

        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "galois_poly_v0".into();
        let func = FuncDecl::new_plugin(
            vec![],
            vec![(0, p0_size), (0, p1_size), (0, q_size)],
            GaloisPolyV0::NAME.into(),
            "prod_eq".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &fun_store,
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
                .map(|_| F61p::random(&mut rng).into_int())
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

    #[test]
    fn test_poly_shift_eq() {
        // Test correct triple verifies
        test_shift_eq_with_degree(0, true);
        test_shift_eq_with_degree(1, true);
        test_shift_eq_with_degree(10, true);
        // Test random triple fails
        test_shift_eq_with_degree(0, false);
        test_shift_eq_with_degree(1, false);
        test_shift_eq_with_degree(10, false);
    }

    fn test_shift_eq_with_degree(degree: u64, should_verify: bool) {
        let p_size = degree + 1;
        let wire_count = 2 * p_size + 1;

        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "galois_poly_v0".into();
        let func = FuncDecl::new_plugin(
            vec![],
            vec![(0, p_size), (0, 1), (0, p_size)],
            GaloisPolyV0::NAME.into(),
            "shift_eq".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);

        let mut gates = vec![GateM::New(0, 0, wire_count)];
        // Add witness gates for p
        for i in 0..p_size {
            gates.push(GateM::Witness(0, i))
        }
        // Add witness gate for c
        gates.push(GateM::Witness(0, p_size));
        // Add instance gates for q
        for i in p_size + 1..wire_count {
            gates.push(GateM::Instance(0, i))
        }
        gates.push(GateM::Call(Box::new((
            name.clone(),
            vec![],
            vec![
                (0, p_size - 1),
                (p_size, p_size),
                (p_size + 1, wire_count - 1),
            ],
        ))));

        let mut rng = AesRng::new();

        let (mut p0, mut p1, q) = get_shift_triple::<_, F61p>(&mut rng, degree as usize);
        p0.append(&mut p1);
        let witnesses = if should_verify {
            vec![p0]
        } else {
            vec![(0..p_size + 1)
                .map(|_| F61p::random(&mut rng).into_int())
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
