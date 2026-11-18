#![doc = include_str!("../../HIGHER_DEGREE_COMMITMENT.md")]

mod commitment_polynomial;

pub mod batch_verification;

pub(crate) use batch_verification::{BatchProverAccumulator, BatchVerifierAccumulator};

pub use commitment_polynomial::{CommitmentPolynomialProver, CommitmentPolynomialVerifier};
