#![doc = include_str!("../../HIGHER_DEGREE_COMMITMENT.md")]

mod commitment_polynomial;

pub mod batch_verification;

use swanky_field_binary::F2;

use crate::{parameters::FLambda, vole::ExtensionFieldLifterF2FLambda};

use batch_verification::{BatchProverAccumulator, BatchVerifierAccumulator};

pub use commitment_polynomial::{CommitmentPolynomialProver, CommitmentPolynomialVerifier};

/// Prover accumulator specialized to `F2`/`P::FLambda` with power-basis lifting.
pub(crate) type BatchProverAccumulatorF2FLambda<P> =
    BatchProverAccumulator<F2, FLambda<P>, ExtensionFieldLifterF2FLambda<P>>;

/// Verifier accumulator specialized to `F2`/`P::FLambda` with power-basis lifting.
pub(crate) type BatchVerifierAccumulatorF2FLambda<P> =
    BatchVerifierAccumulator<F2, FLambda<P>, ExtensionFieldLifterF2FLambda<P>>;
