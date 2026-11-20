#![doc = include_str!("../../HIGHER_DEGREE_COMMITMENT.md")]

mod commitment_polynomial;

pub(crate) mod batch_verification;
pub(crate) use batch_verification::{BatchProverAccumulator, BatchVerifierAccumulator};

pub(crate) use commitment_polynomial::{CommitmentPolynomialProver, CommitmentPolynomialVerifier};
