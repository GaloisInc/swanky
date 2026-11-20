//! Batch constraint verification from the
//! [Batched verification](crate::higher_degree_commitment#batched-verification) protocol.
//!
//! [`BatchProverAccumulator`] builds the masked polynomial $`\pi(t)`$ (step 6), and
//! [`BatchVerifierAccumulator`] checks it at $`\Delta`$ (step 7).

use std::marker::PhantomData;

use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;
use swanky_error::{ErrorKind, Result, ensure};
use swanky_field::{FiniteField, IsSubFieldOf};

use crate::vole::combine;

use super::{CommitmentPolynomialProver, CommitmentPolynomialVerifier};

/// Evaluate the polynomial at `point` using Horner's method.
/// Coefficients are ordered from constant to highest degree.
fn evaluate_poly<FE: FiniteField>(coefficients: &[FE], point: FE) -> FE {
    coefficients
        .iter()
        .rev()
        .fold(FE::ZERO, |acc, c| acc * point + *c)
}

/// The transmitted coefficients of the masked polynomial $`\pi(t)`$ (step 6).
/// The zero coefficient at degree $`d`$ is omitted.
#[derive(Clone, Debug)]
pub(crate) struct ZeroPolynomialCoefficients<FE: FiniteField> {
    coefficients: Vec<FE>,
}

impl<FE: FiniteField> ZeroPolynomialCoefficients<FE> {
    /// Return the batch degree $`d`$, equal to the number of transmitted coefficients.
    pub fn max_degree(&self) -> usize {
        self.coefficients.len()
    }

    /// Return the coefficients of $`\pi(t)`$ in increasing degree order.
    pub fn coefficients(&self) -> &[FE] {
        &self.coefficients
    }
}

/// Accumulate prover constraints and form the masked polynomial $`\pi(t)`$ (step 6).
/// Constraints are aligned to the maximum degree fixed at construction.
pub(crate) struct BatchProverAccumulator<F: IsSubFieldOf<FE>, FE: FiniteField> {
    /// Coefficients of the aggregate $`A(t)`$ in increasing degree order.
    aggregate: Vec<FE>,
    phantom: PhantomData<F>,
}

impl<F: IsSubFieldOf<FE>, FE: FiniteField> BatchProverAccumulator<F, FE> {
    /// Create a prover accumulator with `max_degree` as the batch degree $`d`$ (step 1).
    /// A maximum degree of zero represents a batch with no higher degree constraints.
    pub(crate) fn new(max_degree: usize) -> Self {
        Self {
            aggregate: if max_degree == 0 {
                Vec::new()
            } else {
                vec![FE::ZERO; max_degree + 1]
            },
            phantom: PhantomData,
        }
    }

    /// Return the number of VOLEs needed to mask a batch of degree `max_degree` (steps 2–3).
    /// No masks are needed when `max_degree` is zero or one.
    pub(crate) fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * F::DegreeModulo::USIZE
    }

    /// Add a constraint to $`A(t)`$, weighting it by `challenge` and aligning its degree (step 6).
    /// Return an error if the batch degree is zero, the constraint exceeds it, or its committed
    /// value is nonzero.
    pub(crate) fn push_constraint(
        &mut self,
        constraint: &CommitmentPolynomialProver<F, FE>,
        challenge: FE,
    ) -> Result<()> {
        let max_degree = self.max_degree();
        ensure!(
            max_degree > 0 && constraint.degree() <= max_degree,
            ErrorKind::OtherError,
            "Higher degree constraint has degree {}, but the accumulator is configured for maximum degree {}",
            constraint.degree(),
            max_degree
        );

        ensure!(
            constraint.highest_degree() == F::ZERO,
            ErrorKind::OtherError,
            "Higher degree constraint does not evaluate to zero"
        );

        let shift = max_degree - constraint.degree();
        for (i, coefficient) in constraint.lower_coefficients().iter().enumerate() {
            self.aggregate[i + shift] += challenge * *coefficient;
        }

        // NOTE: the highest coefficient is checked to be zero above, so we omit adding
        // the highest-degree coefficient multiplied by the challenge:
        // `self.aggregate[shift + constraint.degree()] += constraint.highest_degree() * challenge;`

        Ok(())
    }

    /// Return the maximum constraint degree $`d`$ fixed at construction (step 1).
    pub(crate) fn max_degree(&self) -> usize {
        self.aggregate.len().saturating_sub(1)
    }

    /// Return the degree-$`d`$ coefficient of $`A(t)`$, which is zero for accepted constraints (step 6).
    /// An empty batch returns zero.
    #[cfg(debug_assertions)]
    pub(crate) fn top_coefficient(&self) -> FE {
        self.aggregate.last().copied().unwrap_or(FE::ZERO)
    }

    /// Evaluate the aggregate $`A(t)`$ at `point`, before adding the masks (step 6).
    #[cfg(test)]
    pub(crate) fn evaluate_at(&self, point: FE) -> FE {
        evaluate_poly(&self.aggregate, point)
    }

    /// Mask the aggregate with VOLEs (step3) and return the transmitted coefficients of $`\pi(t)`$ (step 6).
    /// Both input streams must have the length returned by [`Self::mask_vole_count`].
    pub(crate) fn finish(
        self,
        mask_values: &[F],
        mask_masks: &[FE],
    ) -> Result<ZeroPolynomialCoefficients<FE>> {
        debug_assert_eq!(self.top_coefficient(), FE::ZERO);
        let degree = self.max_degree();
        let expected_mask_count = Self::mask_vole_count(degree);

        ensure!(
            mask_values.len() == expected_mask_count && mask_masks.len() == expected_mask_count,
            ErrorKind::OtherError,
            "Wrong number of higher degree mask VOLEs: Expected {}, got {} values and {} masks",
            expected_mask_count,
            mask_values.len(),
            mask_masks.len()
        );

        // Let's start setting $`\pi(t)`$ as $`A(t)`$.
        let mut pi = self.aggregate[..degree].to_vec();

        // Organize the flat streams into per-mask blocks and compose each into a full-field mask.
        let (values_blocks, _) = Array::<F, F::DegreeModulo>::slice_as_chunks(mask_values);
        let (masks_blocks, _) = Array::<FE, F::DegreeModulo>::slice_as_chunks(mask_masks);
        for (j, (values, masks)) in values_blocks.iter().zip(masks_blocks).enumerate() {
            // First, compose the sVOLE blocks into the mask $`\sigma_j(t)=w_j+s_jt`$,
            // this is step 3.
            let s_j = F::form_superfield(values);
            let w_j = combine(masks);

            // Second, add $`\sum_{j=1}^{d-1}t^{j-1}\sigma_{s_j}(t)`$ to $`A(t)`$,
            // this is step 6.
            pi[j] += w_j;
            pi[j + 1] += s_j;
        }

        Ok(ZeroPolynomialCoefficients { coefficients: pi })
    }
}

/// Accumulate constraint evaluations and check $`\pi(\Delta)=q`$ (step 7).
/// Constraints are aligned to the maximum degree fixed at construction.
pub(crate) struct BatchVerifierAccumulator<F: IsSubFieldOf<FE>, FE: FiniteField> {
    /// Constraint evaluations weighted by their challenges and grouped by degree.
    aggregates: Vec<FE>,
    phantom: PhantomData<F>,
}

impl<F: IsSubFieldOf<FE>, FE: FiniteField> BatchVerifierAccumulator<F, FE> {
    /// Create a verifier accumulator with `max_degree` as the batch degree $`d`$ (step 1).
    /// A maximum degree of zero represents a batch with no higher degree constraints.
    pub(crate) fn new(max_degree: usize) -> Self {
        Self {
            aggregates: if max_degree == 0 {
                Vec::new()
            } else {
                vec![FE::ZERO; max_degree + 1]
            },
            phantom: PhantomData,
        }
    }

    /// Return the number of VOLEs needed to mask a batch of degree `max_degree` (steps 2–3).
    /// No masks are needed when `max_degree` is zero or one.
    pub(crate) fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * F::DegreeModulo::USIZE
    }

    /// Add a verifier commitment, weighted by `challenge`, for degree alignment (step 7).
    /// Return an error if the batch degree is zero or the commitment exceeds it.
    pub(crate) fn push_constraint(
        &mut self,
        constraint: &CommitmentPolynomialVerifier<F, FE>,
        challenge: FE,
    ) -> Result<()> {
        // Group the challenge-weighted evaluations by degree; the $\Delta^{d-d_i}$ alignment is
        // applied after traversal using the maximum degree fixed at construction.
        let max_degree = self.max_degree();
        let degree = constraint.degree();
        ensure!(
            max_degree != 0 && degree <= max_degree,
            ErrorKind::OtherError,
            "Higher degree constraint has degree {}, but the accumulator is configured for maximum degree {}",
            degree,
            max_degree
        );

        self.aggregates[degree] += challenge * constraint.evaluation();
        Ok(())
    }

    /// Return the maximum constraint degree $`d`$ fixed at construction (step 1).
    pub(crate) fn max_degree(&self) -> usize {
        self.aggregates.len().saturating_sub(1)
    }

    /// Check the coefficient count and verify $`\pi(\Delta)=q`$ using the mask tags (step 7).
    /// Return an error if verification fails or the tag count differs from [`Self::mask_vole_count`].
    pub(crate) fn finish(
        &self,
        delta: FE,
        mask_tags: &[FE],
        prover_coefficients: &ZeroPolynomialCoefficients<FE>,
    ) -> Result<()> {
        // The degree-$d$ coefficient of $`\pi(t)`$ is zero and omitted, so the prover sends exactly
        // $`d`$ coefficients. This also enforces the degree bound on $`\pi`$.
        let max_higher_degree = self.max_degree();
        ensure!(
            prover_coefficients.max_degree() == max_higher_degree,
            ErrorKind::OtherError,
            "Verification failed: expected {} higher degree commitment coefficients, got {}",
            max_higher_degree,
            prover_coefficients.max_degree()
        );

        let expected_mask_count = Self::mask_vole_count(max_higher_degree);
        ensure!(
            mask_tags.len() == expected_mask_count,
            ErrorKind::OtherError,
            "Wrong number of higher degree mask VOLEs: Expected {}, got {}",
            expected_mask_count,
            mask_tags.len()
        );

        if max_higher_degree == 0 {
            return Ok(());
        }

        // The value $`q`$ in step 7 for the verifier is the sum of
        // constraint contributions and mask contributions, each part
        // computed and added to the expected $`q`$ below.

        // Constraint contributions: $\sum_i\chi_i\Delta^{d-d_i}\gamma_i$.
        let mut expected = FE::ZERO;
        for (degree, aggregate) in self.aggregates.iter().enumerate() {
            // TODO: optimization, use the precomputed powers of delta here.
            // Benefits may be marginal for circuits using many higher-degree polynomial commitments,
            // since recomputation only happens at the final step of the protocol and are
            // independent from the number of higher-degree polynomial commmitments.
            expected += delta.pow_var_time((max_higher_degree - degree) as u128) * *aggregate;
        }

        // Mask contributions: $`\sum_j\Delta^{j-1}\nu_j`$, organizing the flat stream into per-mask
        // blocks and composing each into $`nu_j`$.
        let mut delta_power = FE::ONE;
        let (tag_blocks, _) = Array::<FE, F::DegreeModulo>::slice_as_chunks(mask_tags);
        for block in tag_blocks {
            // step 3.
            let nu_j = combine(block);

            // step 7 adding the mask multiplied by $\Delta^{j-1}$.
            expected += delta_power * nu_j;
            delta_power *= delta;
        }

        // Evaluate the prover's $`\pi(\Delta)`$ and compare.
        let pi_at_delta = evaluate_poly(prover_coefficients.coefficients(), delta);

        ensure!(
            pi_at_delta == expected,
            ErrorKind::OtherError,
            "Verification failed: Higher degree constraint check failed"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vole::combine;
    use proptest::{collection::vec, prelude::*, test_runner::TestCaseResult};
    use rand::{RngExt, SeedableRng};
    use swanky_field_binary::{F2, F8b, F64b, F128b};
    use swanky_rng::SwankyRng;

    fn vole_streams<F: IsSubFieldOf<FE>, FE: FiniteField>(
        rng: &mut SwankyRng,
        delta: FE,
        count: usize,
    ) -> (Vec<F>, Vec<FE>, Vec<FE>) {
        let values: Vec<F> = (0..count).map(|_| F::random(rng)).collect();
        let masks: Vec<FE> = (0..count).map(|_| FE::random(rng)).collect();
        let tags = (0..count).map(|k| values[k] * delta + masks[k]).collect();
        (values, masks, tags)
    }

    // Strategy to generate pairs `(d, degrees)` where `d` is a maximum degree
    // and `degrees` is a vector of polynomial degrees less than or equal to `d`.
    fn strategy_degrees(min_degree: usize) -> impl Strategy<Value = (usize, Vec<usize>)> {
        (min_degree..=20).prop_flat_map(|d| (Just(d), vec(0..=d, 0..=if d == 0 { 0 } else { 20 })))
    }

    /// Generate a random polynomial committing to zero with the given `degree` (step 4).
    fn random_polynomial_constraint<F: IsSubFieldOf<FE>, FE: FiniteField>(
        rng: &mut SwankyRng,
        degree: usize,
    ) -> CommitmentPolynomialProver<F, FE> {
        CommitmentPolynomialProver::from_parts(
            (0..degree).map(|_| FE::random(rng)).collect(),
            F::ZERO,
        )
    }

    /// Compute a reference field power by repeated multiplication.
    fn spec_power<FE: FiniteField>(point: FE, degree: usize) -> FE {
        (0..degree).fold(FE::ONE, |acc, _| acc * point)
    }

    /// Evaluate a polynomial directly from its coefficients for comparison with the implementation.
    fn spec_polynomial_evaluation<FE: FiniteField>(coefficients: &[FE], point: FE) -> FE {
        coefficients
            .iter()
            .enumerate()
            .map(|(k, c)| *c * spec_power(point, k))
            .sum()
    }

    // test1: Degree bounds and coefficient count.
    // Both accumulators accept constraints within the configured maximum degree and reject larger ones.
    // The prover sends exactly max_degree coefficients, and the verifier accepts the resulting proof.
    fn degree_bounds_and_coefficient_count<F: IsSubFieldOf<FE>, FE: FiniteField>(
        seed: [u8; 16],
        d: usize,
        num_polynomials: usize,
        excess: usize,
    ) -> TestCaseResult {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let delta = FE::random(rng);
        let mut prover = BatchProverAccumulator::<F, FE>::new(d);
        let mut verifier = BatchVerifierAccumulator::<F, FE>::new(d);
        for _ in 0..num_polynomials {
            let degree = rng.random_range(0..=d);
            let poly = random_polynomial_constraint::<F, FE>(rng, degree);
            let chi = FE::random(rng);
            let gamma = poly.evaluate_at_point(delta);
            prop_assert!(prover.push_constraint(&poly, chi).is_ok());
            let commitment = CommitmentPolynomialVerifier::from_parts(gamma, degree);
            prop_assert!(verifier.push_constraint(&commitment, chi).is_ok());
        }
        let bad = random_polynomial_constraint::<F, FE>(rng, d + excess);
        let chi = FE::random(rng);
        let err_prover = prover.push_constraint(&bad, chi).unwrap_err();
        let bad_verifier =
            CommitmentPolynomialVerifier::from_parts(bad.evaluate_at_point(delta), bad.degree());
        let err_verifier = verifier.push_constraint(&bad_verifier, chi).unwrap_err();
        prop_assert!(
            err_prover
                .to_string()
                .contains("but the accumulator is configured for maximum degree")
        );
        prop_assert!(
            err_verifier
                .to_string()
                .contains("but the accumulator is configured for maximum degree")
        );
        let (values, masks, tags) =
            vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * F::DegreeModulo::USIZE);
        let pi = prover.finish(&values, &masks).unwrap();
        prop_assert_eq!(pi.coefficients().len(), d);
        prop_assert_eq!(pi.max_degree(), d);
        prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        Ok(())
    }

    proptest! {
        #[test]
        fn test1_degree_bounds_and_coefficient_count(
            seed in any::<[u8; 16]>(),
            d in 1usize..=20,
            num_polynomials in 0usize..=20,
            excess in 1usize..=4,
        ) {
            degree_bounds_and_coefficient_count::<F2, F128b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F2, F64b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F8b, F128b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F128b, F128b>(
                seed, d, num_polynomials, excess,
            )?;
        }
    }

    // test2: Incremental aggregation.
    // After each constraint is pushed, the prover’s aggregate evaluation matches an independent reference
    // sum with challenge scaling and degree alignment.
    // The verifier is checked against that reference too, using delta = 0, 1, and a random value.
    fn incremental_aggregation_matches_reference<F: IsSubFieldOf<FE>, FE: FiniteField>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
    ) -> TestCaseResult {
        let rng = &mut SwankyRng::from_seed(seed.into());
        for delta in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let mut prover = BatchProverAccumulator::<F, FE>::new(d);
            let mut verifier = BatchVerifierAccumulator::<F, FE>::new(d);
            let (_, _, tags) =
                vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * F::DegreeModulo::USIZE);
            let (tag_blocks, _) = Array::<FE, F::DegreeModulo>::slice_as_chunks(&tags);
            let mask: FE = tag_blocks
                .iter()
                .enumerate()
                .map(|(j, block)| spec_power(delta, j) * combine(block))
                .sum();
            let mut oracle = ZeroPolynomialCoefficients {
                coefficients: vec![FE::ZERO; d],
            };
            if d > 0 {
                oracle.coefficients[0] = mask;
            }
            let mut expected = FE::ZERO;
            prop_assert_eq!(prover.evaluate_at(delta), expected);
            prop_assert!(verifier.finish(delta, &tags, &oracle).is_ok());
            for (i, &degree) in degrees.iter().enumerate() {
                let rho = random_polynomial_constraint::<F, FE>(rng, degree);
                let chi = [FE::ONE, FE::ZERO, FE::random(rng)][i % 3];
                expected += chi
                    * spec_power(delta, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), delta);
                prover.push_constraint(&rho, chi).unwrap();
                let commitment =
                    CommitmentPolynomialVerifier::from_parts(rho.evaluate_at_point(delta), degree);
                verifier.push_constraint(&commitment, chi).unwrap();
                prop_assert_eq!(prover.evaluate_at(delta), expected);
                // A constant proof checks the verifier against the independent scalar reference.
                oracle.coefficients[0] = expected + mask;
                prop_assert!(verifier.finish(delta, &tags, &oracle).is_ok());
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test2_incremental_aggregation_matches_reference(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(0),
        ) {
            incremental_aggregation_matches_reference::<F2, F128b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F2, F64b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F8b, F128b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F128b, F128b>(
                seed, d, &degrees,
            )?;
        }
    }

    // test3: Coefficient tampering.
    // An honest proof passes. Changing one transmitted coefficient by a nonzero amount causes rejection.
    // A nonzero delta ensures the change affects the evaluation.
    fn tampering_coefficient<F: IsSubFieldOf<FE>, FE: FiniteField>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
        coefficient: usize,
    ) -> TestCaseResult {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let delta = FE::random_nonzero(rng);
        let mut prover = BatchProverAccumulator::<F, FE>::new(d);
        let mut verifier = BatchVerifierAccumulator::<F, FE>::new(d);
        for &degree in degrees {
            let rho = random_polynomial_constraint::<F, FE>(rng, degree);
            let chi = FE::random(rng);
            prover.push_constraint(&rho, chi).unwrap();
            let commitment =
                CommitmentPolynomialVerifier::from_parts(rho.evaluate_at_point(delta), degree);
            verifier.push_constraint(&commitment, chi).unwrap();
        }
        let (values, masks, tags) =
            vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * F::DegreeModulo::USIZE);
        let mut pi = prover.finish(&values, &masks).unwrap();
        prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        pi.coefficients[coefficient % d] += FE::random_nonzero(rng);
        let err = verifier.finish(delta, &tags, &pi).unwrap_err();

        prop_assert!(
            err.to_string()
                .contains("Verification failed: Higher degree constraint check failed")
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn test3_tampering_coefficient(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(1),
            coefficient in 0usize..20,
        ) {
            tampering_coefficient::<F2, F128b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F2, F64b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F8b, F128b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F128b, F128b>(
                seed, d, &degrees, coefficient,
            )?;
        }
    }

    // test4: Nonzero committed values.
    // The prover rejects a constraint whose highest coefficient is non-zero (the committed value),
    // including when its challenge is zero.
    fn nonzero_committed_value_is_rejected<F: IsSubFieldOf<FE>, FE: FiniteField>(
        seed: [u8; 16],
        d: usize,
        degree: usize,
    ) -> TestCaseResult {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let rho = random_polynomial_constraint::<F, FE>(rng, degree % (d + 1))
            .addc(F::random_nonzero(rng));
        for chi in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let mut prover = BatchProverAccumulator::<F, FE>::new(d);

            let err = prover.push_constraint(&rho, chi).unwrap_err();
            prop_assert!(
                err.to_string()
                    .contains("Higher degree constraint does not evaluate to zero")
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test4_nonzero_committed_value_is_rejected(
            seed in any::<[u8; 16]>(),
            d in 1usize..=20,
            degree in 0usize..=20,
        ) {
            nonzero_committed_value_is_rejected::<F2, F128b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F2, F64b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F8b, F128b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F128b, F128b>(seed, d, degree)?;
        }
    }

    // test5: Mask stream lengths.
    // Both sides accept correctly sized mask streams and reject streams that are too short or too long.
    // This includes degrees zero and one, which require no masks.
    fn malformed_mask_streams_are_rejected<F: IsSubFieldOf<FE>, FE: FiniteField>(
        d: usize,
    ) -> TestCaseResult {
        for d in [0, 1, d] {
            let n = d.saturating_sub(1) * F::DegreeModulo::USIZE;
            let values = vec![F::ZERO; n + 1];
            let masks = vec![FE::ZERO; n + 1];
            let pi = ZeroPolynomialCoefficients {
                coefficients: vec![FE::ZERO; d],
            };
            let prover = || BatchProverAccumulator::<F, FE>::new(d);
            let verifier = || BatchVerifierAccumulator::<F, FE>::new(d);
            prop_assert!(prover().finish(&values[..n], &masks[..n]).is_ok());
            prop_assert!(verifier().finish(FE::ONE, &masks[..n], &pi).is_ok());
            for length in [n.saturating_sub(1), n + 1] {
                if length == n {
                    continue;
                }
                let prover_err1 = prover().finish(&values[..length], &masks[..n]).unwrap_err();
                prop_assert!(
                    prover_err1
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
                let prover_err2 = prover().finish(&values[..n], &masks[..length]).unwrap_err();
                prop_assert!(
                    prover_err2
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
                let verifier_err = verifier()
                    .finish(FE::ONE, &masks[..length], &pi)
                    .unwrap_err();
                prop_assert!(
                    verifier_err
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test5_malformed_mask_streams_are_rejected(d in 0usize..=20) {
            malformed_mask_streams_are_rejected::<F2, F128b>(d)?;
            malformed_mask_streams_are_rejected::<F2, F64b>(d)?;
            malformed_mask_streams_are_rejected::<F8b, F128b>(d)?;
            malformed_mask_streams_are_rejected::<F128b, F128b>(d)?;
        }
    }

    // 6. test6: Masking arithmetic.
    // The finished polynomial’s evaluation matches an independent reference combining aligned constraints
    // and shifted VOLE masks.
    // It checks a random evaluation point, checks delta = 0, 1, and a random value, verifies
    // the lifted VOLE correlation, and confirms verifier acceptance.
    fn masking_arithmetic_matches_reference<F: IsSubFieldOf<FE>, FE: FiniteField>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
    ) -> TestCaseResult {
        let rng = &mut SwankyRng::from_seed(seed.into());
        for delta in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let point = FE::random(rng);
            let mut prover = BatchProverAccumulator::<F, FE>::new(d);
            let mut verifier = BatchVerifierAccumulator::<F, FE>::new(d);
            let (mut expected, mut expected_delta) = (FE::ZERO, FE::ZERO);
            for &degree in degrees {
                let rho = random_polynomial_constraint::<F, FE>(rng, degree);
                let chi = FE::random(rng);
                prover.push_constraint(&rho, chi).unwrap();
                let commitment =
                    CommitmentPolynomialVerifier::from_parts(rho.evaluate_at_point(delta), degree);
                verifier.push_constraint(&commitment, chi).unwrap();
                expected += chi
                    * spec_power(point, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), point);
                expected_delta += chi
                    * spec_power(delta, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), delta);
            }
            let (values, masks, tags) =
                vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * F::DegreeModulo::USIZE);
            for j in 0..d.saturating_sub(1) {
                let block = j * F::DegreeModulo::USIZE..(j + 1) * F::DegreeModulo::USIZE;
                let s = F::form_superfield((&values[block.clone()]).try_into().unwrap());
                let w = combine(&masks[block.clone()]);
                prop_assert_eq!(combine(&tags[block]), w + s * delta);
                expected += spec_power(point, j) * (w + s * point);
                expected_delta += spec_power(delta, j) * (w + s * delta);
            }
            let pi = prover.finish(&values, &masks).unwrap();
            prop_assert_eq!(
                spec_polynomial_evaluation(pi.coefficients(), point),
                expected
            );
            prop_assert_eq!(
                spec_polynomial_evaluation(pi.coefficients(), delta),
                expected_delta
            );
            prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test6_masked_polynomial_matches_reference(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(0),
        ) {
            masking_arithmetic_matches_reference::<F2, F128b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F2, F64b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F8b, F128b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F128b, F128b>(seed, d, &degrees)?;
        }
    }
}
