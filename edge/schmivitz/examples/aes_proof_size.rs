//! Prove the packaged AES-256 SIEVE IR circuit and report the estimated proof size.
//!
//! Run with:
//! ```text
//! cargo run --release -p schmivitz --example aes_proof_size
//! ```
//!
//! Pass `--no-default-features` to measure the $`\lambda = 128`$ variant instead.

use merlin::Transcript;
use schmivitz::{
    Proof,
    circuit::load_circuit_from_strings_prover,
    circuit_validator::validate_circuit,
    parameters::{REPETITION_PARAM, SECURITY_PARAM, VOLE_SIZE_PARAM},
    vole::functionality::{VoleProver, VoleVerifier},
};
use std::time::Instant;

/// The circuit and its witness are compiled in so the example needs no arguments.
///
/// Note that the "256" here is the AES key size, and is unrelated to the
/// [security parameter](SECURITY_PARAM).
const CIRCUIT: &str = include_str!("../circuits/aes_256_conv.sieve");
const PRIVATE_INPUT: &str = include_str!("../circuits/aes_256_conv_private.sieve");

/// A fresh transcript. The prover and the verifier must start from identical transcripts.
fn transcript() -> Transcript {
    Transcript::new(b"schmivitz aes_proof_size example")
}

fn main() -> swanky_error::Result<()> {
    println!(
        "parameters: lambda = {SECURITY_PARAM}, r = {VOLE_SIZE_PARAM}, tau = {REPETITION_PARAM}"
    );

    let t = Instant::now();
    let circuit = load_circuit_from_strings_prover(CIRCUIT, PRIVATE_INPUT)?;
    validate_circuit(&circuit)?;
    println!("parsed and validated circuit in {:?}", t.elapsed());

    let t = Instant::now();
    let proof = Proof::<VoleProver, VoleVerifier>::prove_with_circuit(
        &circuit,
        &mut transcript(),
        &mut rand::rng(),
    )?;
    println!("proved in {:?}", t.elapsed());

    // Verify before reporting a size, so we're describing a proof that actually checks out.
    let t = Instant::now();
    proof.verify_with_circuit(&circuit, &mut transcript())?;
    println!("verified in {:?}", t.elapsed());

    let bytes = proof.proof_size_estimate();
    println!(
        "estimated proof size: {bytes} bytes ({:.1} KiB)",
        bytes as f64 / 1024.0
    );

    // `proof_size_estimate` is an estimate, and currently an imprecise one: it omits
    // `assert_zero_commitment`, hardcodes the degree-1 commitment at 16 bytes rather than
    // `SECURITY_PARAM / 8`, and computes `u_tilda` as `SECURITY_PARAM + B / 8` where
    // `(SECURITY_PARAM + B) / 8` was intended. It is also not a serialized length, since the
    // proof has no serialization yet.
    Ok(())
}
