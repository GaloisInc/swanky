//! Commitment polynomials from the
//! [Commitment polynomials](crate::higher_degree_commitment#commitment-polynomials) protocol.
//!
//! [`CommitmentPolynomialProver`] and [`CommitmentPolynomialVerifier`] implement the
//! [gate operations](crate::higher_degree_commitment#gate-by-gate-commitment-propagation).

use std::marker::PhantomData;

use swanky_field::{FiniteField, IsSubFieldOf};

use super::power;

/// The prover's [VOLE commitment](crate::higher_degree_commitment#commitment-polynomials) to a value in `F`.
/// The highest-degree coefficient holds that value; lower coefficients in `FE` mask it.
#[derive(Clone, Debug)]
pub struct CommitmentPolynomialProver<F: FiniteField, FE: FiniteField>
where
    F: IsSubFieldOf<FE>,
{
    lower_coefficients: Vec<FE>,
    highest_degree: F,
}

impl<F: FiniteField, FE: FiniteField> CommitmentPolynomialProver<F, FE>
where
    F: IsSubFieldOf<FE>,
{
    /// Create a commitment polynomial from a base VOLE.
    pub fn from_base_vole(value: F, mask: FE) -> Self {
        Self {
            lower_coefficients: vec![mask],
            highest_degree: value,
        }
    }

    /// Create a commitment polynomial directly from its lower coefficients
    /// and the highest-degree coefficient.
    #[cfg(test)]
    pub fn from_parts(lower_coefficients: Vec<FE>, highest_degree: F) -> Self {
        Self {
            lower_coefficients,
            highest_degree,
        }
    }

    /// Return the commitment degree.
    pub fn degree(&self) -> usize {
        self.lower_coefficients.len()
    }

    /// Return the lower coefficients.
    pub fn lower_coefficients(&self) -> &[FE] {
        &self.lower_coefficients
    }

    /// Return the highest-degree coefficient $`x`$ (the committed value).
    pub fn highest_degree(&self) -> F {
        self.highest_degree
    }

    /// Evaluate the polynomial at a given point using Horner's method.
    pub fn evaluate_at_point(&self, point: FE) -> FE {
        let mut result: FE = self.highest_degree.into();
        for c in self.lower_coefficients.iter().rev() {
            result = result * point + *c;
        }
        result
    }

    /// Add a constant.
    pub fn addc(&self, c: F) -> Self {
        Self {
            lower_coefficients: self.lower_coefficients.clone(),
            highest_degree: self.highest_degree + c,
        }
    }

    /// Add two commitment polynomials, aligning to the maximum degree.
    pub fn add(&self, other: &Self) -> Self {
        let d1 = self.degree();
        let d2 = other.degree();
        let d = d1.max(d2);

        let mut lower = vec![FE::ZERO; d];

        let shift1 = d - d1;
        for (i, c) in self.lower_coefficients.iter().enumerate() {
            lower[i + shift1] += *c;
        }
        let shift2 = d - d2;
        for (i, c) in other.lower_coefficients.iter().enumerate() {
            lower[i + shift2] += *c;
        }

        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree + other.highest_degree,
        }
    }

    /// Multiply by a constant.
    pub fn mulc(&self, c: F) -> Self {
        let lower = self.lower_coefficients.iter().map(|x| c * *x).collect();
        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree * c,
        }
    }

    /// Multiply two commitment polynomials.
    pub fn mul(&self, other: &Self) -> Self {
        let d1 = self.degree();
        let d2 = other.degree();
        let new_degree = d1 + d2;
        let mut lower = vec![FE::ZERO; new_degree];

        for (i, a) in self.lower_coefficients.iter().enumerate() {
            for (j, b) in other.lower_coefficients.iter().enumerate() {
                lower[i + j] += *a * *b;
            }
        }
        for (j, b) in other.lower_coefficients.iter().enumerate() {
            lower[d1 + j] += self.highest_degree * *b;
        }
        for (i, a) in self.lower_coefficients.iter().enumerate() {
            lower[i + d2] += other.highest_degree * *a;
        }

        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree * other.highest_degree,
        }
    }
}

/// The verifier's [VOLE commitment](crate::higher_degree_commitment#commitment-polynomials).
/// Stores the evaluation at the verifier's key and the commitment degree.
#[derive(Clone, Copy, Debug)]
pub struct CommitmentPolynomialVerifier<F: FiniteField, FE: FiniteField>
where
    F: IsSubFieldOf<FE>,
{
    evaluation: FE,
    degree: usize,
    phantom: PhantomData<F>,
}

impl<F: FiniteField, FE: FiniteField> CommitmentPolynomialVerifier<F, FE>
where
    F: IsSubFieldOf<FE>,
{
    /// Create a degree-one commitment from a [base VOLE](crate::higher_degree_commitment#base-vole) tag.
    pub fn from_base_vole(tag: FE) -> Self {
        Self {
            evaluation: tag,
            degree: 1,
            phantom: PhantomData,
        }
    }

    /// Create a commitment directly from its evaluation and commitment degree.
    #[cfg(test)]
    pub fn from_parts(evaluation: FE, degree: usize) -> Self {
        Self {
            evaluation,
            degree,
            phantom: PhantomData,
        }
    }

    /// Return the commitment degree.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Return the commitment's evaluation at the verifier's key.
    pub fn evaluation(&self) -> FE {
        self.evaluation
    }

    /// Add a constant, using `delta` to update the committed value's contribution.
    /// See the [gate operations](crate::higher_degree_commitment#gate-by-gate-commitment-propagation).
    pub fn addc(&self, c: F, delta: FE) -> Self {
        Self {
            evaluation: self.evaluation + c * power(delta, self.degree),
            ..*self
        }
    }

    /// Add two commitment evaluations, aligning to the maximum degree using `delta`.
    /// See the [gate operations](crate::higher_degree_commitment#gate-by-gate-commitment-propagation).
    pub fn add(&self, other: &Self, delta: FE) -> Self {
        let degree = self.degree.max(other.degree);
        Self {
            evaluation: power(delta, degree - self.degree) * self.evaluation
                + power(delta, degree - other.degree) * other.evaluation,
            degree,
            phantom: PhantomData,
        }
    }

    /// Multiply by a constant, preserving the commitment degree.
    pub fn mulc(&self, c: F) -> Self {
        Self {
            evaluation: c * self.evaluation,
            ..*self
        }
    }

    /// Multiply two commitment evaluations, adding their commitment degrees.
    pub fn mul(&self, other: &Self) -> Self {
        Self {
            evaluation: self.evaluation * other.evaluation,
            degree: self.degree + other.degree,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;
    use rand::SeedableRng;
    use rand::rng;
    use swanky_field::FiniteRing;
    use swanky_field::{FiniteField, IsSubFieldOf};
    use swanky_field_binary::{F2, F8b, F128b};
    use swanky_rng::SwankyRng;

    fn pow_fe<FE: FiniteField>(base: FE, exp: usize) -> FE {
        let mut result = FE::ONE;
        for _ in 0..exp {
            result *= base;
        }
        result
    }

    /// Reference polynomial evaluation independent of `evaluate_at_point`'s Horner
    /// implementation: cross-checks correctness by recomputing the sum directly.
    fn eval_reference<F, FE: FiniteField>(poly: &CommitmentPolynomialProver<F, FE>, point: FE) -> FE
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut acc = FE::ZERO;
        let mut p = FE::ONE;
        for c in poly.lower_coefficients() {
            acc += *c * p;
            p *= point;
        }
        acc + Into::<FE>::into(poly.highest_degree()) * p
    }

    #[test]
    fn from_base_vole_creates_degree_one() {
        let mut rng = rng();
        let value = F2::random(&mut rng);
        let mask = F128b::random(&mut rng);
        let delta = F128b::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F2, F128b>::from_base_vole(value, mask);
        let verifier =
            CommitmentPolynomialVerifier::<F2, F128b>::from_base_vole(mask + value * delta);
        assert_eq!(poly.degree(), 1);
        assert_eq!(poly.lower_coefficients(), &[mask]);
        assert_eq!(poly.highest_degree(), value);
        assert_eq!(verifier.degree(), poly.degree());
        assert_eq!(verifier.evaluation(), poly.evaluate_at_point(delta));
    }

    #[test]
    fn from_parts_round_trip() {
        let mut rng = rng();
        let lower = vec![F128b::random(&mut rng), F128b::random(&mut rng)];
        let highest = F2::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F2, F128b>::from_parts(lower.clone(), highest);
        assert_eq!(poly.lower_coefficients(), &lower[..]);
        assert_eq!(poly.highest_degree(), highest);
        assert_eq!(poly.degree(), 2);
    }

    fn evaluate_at_point_horner<F, FE: FiniteField>(seed: [u8; 16]) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let value = F::random(&mut rng);
        let mask = FE::random(&mut rng);
        let point = FE::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F, FE>::from_base_vole(value, mask);
        let verifier = CommitmentPolynomialVerifier::<F, FE>::from_base_vole(mask + value * point);
        // ρ(t) = mask + value·t
        prop_assert_eq!(poly.evaluate_at_point(point), mask + value * point);
        prop_assert_eq!(verifier.degree(), poly.degree());
        prop_assert_eq!(verifier.evaluation(), poly.evaluate_at_point(point));
        Ok(())
    }

    proptest! {
        #[test]
        fn evaluate_at_point_horner_f128b(seed in any::<[u8; 16]>()) {
            evaluate_at_point_horner::<F2, F128b>(seed)?;
            evaluate_at_point_horner::<F8b, F128b>(seed)?;
            evaluate_at_point_horner::<F128b, F128b>(seed)?;
        }
    }

    fn evaluate_at_point_matches_reference<F, FE: FiniteField>(
        seed: [u8; 16],
        degree: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F, FE>::from_parts(lower, highest);

        for point in [FE::ZERO, FE::ONE, FE::random(&mut rng)] {
            prop_assert_eq!(
                poly.evaluate_at_point(point),
                eval_reference(&poly, point),
                "degree = {}, point = {:?}",
                degree,
                point,
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn evaluate_at_point_matches_reference_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            evaluate_at_point_matches_reference::<F2, F128b>(seed, degree)?;
            evaluate_at_point_matches_reference::<F8b, F128b>(seed, degree)?;
            evaluate_at_point_matches_reference::<F128b, F128b>(seed, degree)?;
        }
    }

    fn addc_correctness<F, FE: FiniteField>(seed: [u8; 16], degree: usize) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let c = F::random(&mut rng);
        let point = FE::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F, FE>::from_parts(lower, highest);
        let result = poly.addc(c);
        prop_assert_eq!(result.highest_degree(), poly.highest_degree() + c);
        prop_assert_eq!(result.lower_coefficients(), poly.lower_coefficients());
        prop_assert_eq!(result.degree(), degree);
        prop_assert_eq!(
            result.evaluate_at_point(point),
            poly.evaluate_at_point(point) + c * pow_fe(point, degree),
        );
        let verifier = CommitmentPolynomialVerifier::<F, FE>::from_parts(
            poly.evaluate_at_point(point),
            degree,
        )
        .addc(c, point);
        prop_assert_eq!(verifier.degree(), result.degree());
        prop_assert_eq!(verifier.evaluation(), result.evaluate_at_point(point));
        Ok(())
    }

    proptest! {
        #[test]
        fn addc_increments_highest_degree_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            addc_correctness::<F2, F128b>(seed, degree)?;
            addc_correctness::<F8b, F128b>(seed, degree)?;
            addc_correctness::<F128b, F128b>(seed, degree)?;
        }
    }

    #[test]
    fn add_same_degree() {
        let mut rng = rng();
        let val_x = F128b::random(&mut rng);
        let val_y = F128b::random(&mut rng);
        let w_x = F128b::random(&mut rng);
        let w_y = F128b::random(&mut rng);
        let point = F128b::random(&mut rng);

        let poly_x = CommitmentPolynomialProver::<F128b, F128b>::from_base_vole(val_x, w_x);
        let poly_y = CommitmentPolynomialProver::<F128b, F128b>::from_base_vole(val_y, w_y);

        let sum = poly_x.add(&poly_y);
        let verifier_x =
            CommitmentPolynomialVerifier::<F128b, F128b>::from_base_vole(w_x + val_x * point);
        let verifier_y =
            CommitmentPolynomialVerifier::<F128b, F128b>::from_base_vole(w_y + val_y * point);
        let verifier_sum = verifier_x.add(&verifier_y, point);
        assert_eq!(sum.degree(), 1);
        assert_eq!(sum.highest_degree(), val_x + val_y);
        assert_eq!(verifier_sum.degree(), sum.degree());
        assert_eq!(verifier_sum.evaluation(), sum.evaluate_at_point(point));
        assert_eq!(
            sum.evaluate_at_point(point),
            poly_x.evaluate_at_point(point) + poly_y.evaluate_at_point(point),
        );
    }

    fn add_correctness<F, FE: FiniteField>(
        seed: [u8; 16],
        degree_a: usize,
        degree_b: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        prop_assume!(degree_a != degree_b);
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower_a = (0..degree_a).map(|_| FE::random(&mut rng)).collect();
        let highest_a = F::random(&mut rng);
        let poly_a = CommitmentPolynomialProver::<F, FE>::from_parts(lower_a, highest_a);
        let lower_b = (0..degree_b).map(|_| FE::random(&mut rng)).collect();
        let highest_b = F::random(&mut rng);
        let poly_b = CommitmentPolynomialProver::<F, FE>::from_parts(lower_b, highest_b);
        let degree = degree_a.max(degree_b);

        let points = [FE::ZERO, FE::ONE, FE::random(&mut rng)];
        let sum = poly_a.add(&poly_b);

        for point in points {
            let verifier_a = CommitmentPolynomialVerifier::<F, FE>::from_parts(
                poly_a.evaluate_at_point(point),
                degree_a,
            );
            let verifier_b = CommitmentPolynomialVerifier::<F, FE>::from_parts(
                poly_b.evaluate_at_point(point),
                degree_b,
            );
            let verifier_sum = verifier_a.add(&verifier_b, point);
            // ρ_sum(t) = t^(d-d_a) ρ_a(t) + t^(d-d_b) ρ_b(t).
            prop_assert_eq!(
                poly_a.evaluate_at_point(point) * pow_fe(point, degree - poly_a.degree())
                    + poly_b.evaluate_at_point(point) * pow_fe(point, degree - poly_b.degree()),
                sum.evaluate_at_point(point),
                "degrees = ({}, {}), point = {:?}",
                poly_a.degree(),
                poly_b.degree(),
                point,
            );
            prop_assert_eq!(verifier_sum.degree(), sum.degree());
            prop_assert_eq!(verifier_sum.evaluation(), sum.evaluate_at_point(point));
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn add_different_degrees_f128b(
            seed in any::<[u8; 16]>(),
            degree_a in 0usize..=128,
            degree_b in 0usize..=128,
        ) {
            add_correctness::<F2, F128b>(seed, degree_a, degree_b)?;
            add_correctness::<F8b, F128b>(seed, degree_a, degree_b)?;
            add_correctness::<F128b, F128b>(seed, degree_a, degree_b)?;
        }
    }

    fn mulc_correctness<F, FE: FiniteField>(seed: [u8; 16], degree: usize) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let poly = CommitmentPolynomialProver::<F, FE>::from_parts(lower, highest);
        let points = [FE::ZERO, FE::ONE, FE::random(&mut rng)];
        for c in [F::ZERO, F::ONE, F::random(&mut rng)] {
            let result = poly.mulc(c);
            prop_assert_eq!(result.degree(), degree);
            for point in points {
                let verifier = CommitmentPolynomialVerifier::<F, FE>::from_parts(
                    poly.evaluate_at_point(point),
                    degree,
                )
                .mulc(c);
                prop_assert_eq!(
                    c * poly.evaluate_at_point(point),
                    result.evaluate_at_point(point),
                    "degree = {}, constant = {:?}, point = {:?}",
                    degree,
                    c,
                    point,
                );
                prop_assert_eq!(verifier.degree(), result.degree());
                prop_assert_eq!(verifier.evaluation(), result.evaluate_at_point(point));
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn mulc_correctness_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            mulc_correctness::<F2, F128b>(seed, degree)?;
            mulc_correctness::<F8b, F128b>(seed, degree)?;
            mulc_correctness::<F128b, F128b>(seed, degree)?;
        }
    }

    fn mul_correctness<F, FE: FiniteField>(
        seed: [u8; 16],
        degree_a: usize,
        degree_b: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower_a = (0..degree_a).map(|_| FE::random(&mut rng)).collect();
        let highest_a = F::random(&mut rng);
        let poly_a = CommitmentPolynomialProver::<F, FE>::from_parts(lower_a, highest_a);
        let lower_b = (0..degree_b).map(|_| FE::random(&mut rng)).collect();
        let highest_b = F::random(&mut rng);
        let poly_b = CommitmentPolynomialProver::<F, FE>::from_parts(lower_b, highest_b);
        let product = poly_a.mul(&poly_b);
        prop_assert_eq!(product.degree(), degree_a + degree_b);

        for point in [FE::ZERO, FE::ONE, FE::random(&mut rng)] {
            let verifier_a = CommitmentPolynomialVerifier::<F, FE>::from_parts(
                poly_a.evaluate_at_point(point),
                degree_a,
            );
            let verifier_b = CommitmentPolynomialVerifier::<F, FE>::from_parts(
                poly_b.evaluate_at_point(point),
                degree_b,
            );
            let verifier_product = verifier_a.mul(&verifier_b);
            prop_assert_eq!(
                poly_a.evaluate_at_point(point) * poly_b.evaluate_at_point(point),
                product.evaluate_at_point(point),
                "degrees = ({}, {}), point = {:?}",
                degree_a,
                degree_b,
                point,
            );
            prop_assert_eq!(verifier_product.degree(), product.degree());
            prop_assert_eq!(
                verifier_product.evaluation(),
                product.evaluate_at_point(point)
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn mul_correctness_f128b(
            seed in any::<[u8; 16]>(),
            degree_a in 0usize..=128,
            degree_b in 0usize..=128,
        ) {
            mul_correctness::<F2, F128b>(seed, degree_a, degree_b)?;
            mul_correctness::<F8b, F128b>(seed, degree_a, degree_b)?;
            mul_correctness::<F128b, F128b>(seed, degree_a, degree_b)?;
        }
    }
}
