//! This module implements the Limbo zero knowledge proof protocol.
//!
//! Limbo is an MPC-in-the-head protocol that uses a "compression" technique to
//! optimize the check that multiplications are done correctly. To prove something
//! using Limbo you need to select a _compression factor_ (a.k.a. how much you want
//! to compress the multiplications by each round) and a _number of repetitions_,
//! which denotes how many times to run the MPC-in-the-head protocol. The soundness
//! of the protocol is effected by both of these parameters (alongside the field size);
//! see the [Limbo paper](https://eprint.iacr.org/2021/215) for more details on secure
//! settings of these parameters.

use crate::cache::Cache;
use crate::proof_single::ProofSingle;
use rand::SeedableRng;
use rayon::prelude::*;
use simple_arith_circuit::Circuit;
use swanky_error::{ErrorKind, Result, bail, ensure};
use swanky_field::FiniteField;
use swanky_rng::SwankyRng;

/// The inferno proof. `N` denotes the number of parties in each MPC execution.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Proof<F: FiniteField, const N: usize> {
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    proofs: Vec<ProofSingle<F, N>>,
}

impl<F: FiniteField, const N: usize> Proof<F, N> {
    /// Construct a proof for `circuit` with `witness`, using the provided compression factor
    /// and number of repetitions.
    ///
    /// # Panics
    ///
    /// Panics if (1) `witness` is not of length equal to the number of inputs to `circuit`,
    /// (2) `circuit` does not contain exactly one output wire, and
    /// (3) `N` is not a power of two or `N > 256`.
    pub fn prove(
        circuit: &Circuit<F::PrimeField>,
        witness: &[F::PrimeField],
        compression_factor: usize,
        repetitions: usize,
        rng: &mut SwankyRng,
    ) -> Self {
        assert!(N.is_power_of_two() && N <= 256);
        assert_eq!(witness.len(), circuit.ninputs());
        assert_eq!(circuit.noutputs(), 1);
        let time = std::time::Instant::now();
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        log::debug!("Number of compression rounds = {nrounds}");
        let cache = Cache::new(circuit, compression_factor, true);
        // Each MPC-in-the-head repetition needs its own RNG, so we create the necessary RNGs here.
        let mut rngs: Vec<SwankyRng> = (0..repetitions).map(|_| SwankyRng::from_rng(rng)).collect();
        // Use `rayon` to parallelize the MPC-in-the-head repetitions.
        let proofs: Vec<ProofSingle<F, N>> = rngs
            .par_iter_mut()
            .enumerate()
            .map(|(i, rng)| {
                log::info!("Proof #{}", i + 1);
                let time_ = std::time::Instant::now();
                let proof = ProofSingle::prove(circuit, witness, compression_factor, &cache, rng);
                log::info!("Proof #{} time: {:?}", i + 1, time_.elapsed());
                proof
            })
            .collect();
        log::info!("Proof time: {:?}", time.elapsed());
        Self { proofs }
    }

    /// Verify that the proof on `circuit` is valid, for the given compression factor and
    /// number of repetitions.
    ///
    /// # Panics
    ///
    /// Panics if (1) `circuit` does not contain only one output wire, or
    /// (2) `N` is not a power of two or `N > 256`.
    pub fn verify(
        &self,
        circuit: &Circuit<F::PrimeField>,
        compression_factor: usize,
        repetitions: usize,
    ) -> Result<()> {
        assert!(N.is_power_of_two() && N <= 256);
        assert_eq!(circuit.noutputs(), 1);
        ensure!(
            crate::utils::validate_parameters::<F>(N, compression_factor, repetitions),
            ErrorKind::OtherError,
            "Invalid parameters: ({N}, {compression_factor}, {repetitions}) do not match acceptable settings"
        );
        let time = std::time::Instant::now();
        let cache = Cache::new(circuit, compression_factor, false);
        ensure!(
            self.proofs.len() == repetitions,
            ErrorKind::OtherError,
            "Invalid number of repetitions"
        );
        // Use `rayon` to parallelize the MPC-in-the-head repetitions.
        let results: Vec<Result<()>> = self
            .proofs
            .par_iter()
            .enumerate()
            .map(|(i, proof)| {
                let time_ = std::time::Instant::now();
                log::debug!("Checking proof #{}", i + 1);
                if let Err(e) = proof.verify(circuit, compression_factor, &cache) {
                    bail!(ErrorKind::OtherError, "Proof #{} failed: {}", i + 1, e);
                }
                log::debug!("Verifying proof #{} succeeded.", i + 1);
                log::info!("Proof #{} verification time: {:?}", i + 1, time_.elapsed());
                Ok(())
            })
            .collect();
        log::info!("Verification time: {:?}", time.elapsed());
        match results.into_iter().find_map(|r| r.err()) {
            Some(err) => Err(err),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hashers::{Hashers, Party},
        proof_single::{OpenedPartiesShares, OutputShares, UnopenedParty},
        round::{Round, round_compress_finish, round_compress_start, round1},
        secretsharing::{LinearSharing, SecretSharing},
    };

    use super::*;
    use rand::{RngExt, SeedableRng};
    use swanky_block::Block;
    use swanky_field_binary::F64b;

    const N: usize = 16;
    const K: usize = 8;
    const T: usize = 40;

    macro_rules! test_serialization {
        ($modname: ident, $field: ty) => {
            mod $modname {
                use super::*;
                #[allow(unused_imports)]
                use proptest::prelude::*;
                use swanky_block::Block;

                fn any_seed() -> impl Strategy<Value = Block> {
                    any::<u128>().prop_map(|seed| Block::from(seed))
                }

                proptest! {
                #[test]
                fn serialize_bincode(seed in any_seed()) {
                    let mut rng = SwankyRng::from_seed(seed);
                    let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, SwankyRng>(10, 100, &mut rng);
                    let proof = Proof::<$field, N>::prove(&circuit, &witness, K, T, &mut rng);
                    let serialized = bincode::serialize(&proof).unwrap();
                    let proof: Proof<$field, N> = bincode::deserialize(&serialized).unwrap();
                    assert!(proof.verify(&circuit, K, T).is_ok());
                }
                }
            }
        };
    }

    test_serialization!(test_serialization_f64b, F64b);

    /// See [GitHub Issue #44](https://github.com/GaloisInc/swanky/issues/44).
    ///
    /// Thanks to @rot256 for pointing this out!
    #[test]
    fn poc_frobenius_cancellation() {
        use simple_arith_circuit::{Circuit, Op};
        use swanky_field::FiniteRing;
        use swanky_field_binary::F2;

        type F = F64b;

        let mut rng = SwankyRng::new();

        // Build unsatisfiable circuit with 128 mult gates.
        //
        // Chain A (gates 0-63):   64 self-mults on input a  (x*x = x in GF(2))
        // Chain B (gates 64-127): 64 self-mults on input b
        // output = chain_A_end + a + 1 = a + a + 1 = 1  (always)
        let mut ops: Vec<Op<F2>> = Vec::new();
        ops.push(Op::Mul(0, 0));
        for i in 1..64usize {
            ops.push(Op::Mul(i + 1, i + 1));
        }
        ops.push(Op::Mul(1, 1));
        for i in 1..64usize {
            ops.push(Op::Mul(65 + i, 65 + i));
        }
        ops.push(Op::Add(65, 0));
        ops.push(Op::Constant(F2::ONE));
        ops.push(Op::Add(130, 131));
        let circuit: Circuit<F2> = Circuit::new(2, 1, ops);

        // Confirm unsatisfiability.
        for a in [F2::ZERO, F2::ONE] {
            for b in [F2::ZERO, F2::ONE] {
                let mut w = Vec::new();
                assert_eq!(circuit.eval(&[a, b], &mut w)[0], F2::ONE);
            }
        }

        // --- Cheating prover ---
        // Flip gate outputs at indices 0 and 64.
        // Gate 0 flips chain A from 'a' to '1+a', making output 0.
        // Gate 64 is in chain B (doesn't affect output) but cancels
        // gate 0's error in the round1 linear combination.
        let cheat: std::collections::HashSet<usize> = [0, 64].into_iter().collect();
        let witness = [F2::ZERO; 2];

        let nrounds = crate::utils::nrounds(&circuit, K);
        let mut hashers = Hashers::<N>::new();
        let mut commitments = Vec::with_capacity(nrounds + 2);

        let seeds: [u128; N] = std::array::from_fn(|_| rng.random::<u128>());
        let mut rngs = seeds.map(|s| SwankyRng::from_seed(Block::from(s)));

        let ws: Vec<SecretSharing<F2, N>> = witness
            .iter()
            .map(|w| SecretSharing::new(*w, &mut rngs))
            .collect();

        // Circuit evaluation with cheating on selected mult gates.
        let (mut xs, mut ys, mut zs) = (vec![], vec![], vec![]);
        let mut wires: Vec<SecretSharing<F2, N>> = ws.to_vec();
        let mut gi = 0usize;
        for op in circuit.iter() {
            let v = match *op {
                Op::Add(a, b) => wires[a] + wires[b],
                Op::Sub(a, b) => wires[a] - wires[b],
                Op::Mul(a, b) => {
                    let mut z = wires[a].secret() * wires[b].secret();
                    if cheat.contains(&gi) {
                        z += F2::ONE;
                    }
                    let zsh = SecretSharing::<F2, N>::new(z, &mut rngs);
                    xs.push(wires[a]);
                    ys.push(wires[b]);
                    zs.push(zsh);
                    gi += 1;
                    zsh
                }
                Op::Constant(f) => SecretSharing::new_non_random(f),
                Op::Copy(a) => wires[a],
            };
            wires.push(v);
        }
        let output_share = *wires.last().unwrap();
        assert_eq!(output_share.secret(), F2::ZERO, "cheat must yield output 0");

        // Run the rest of the protocol honestly.
        hashers.hash_circuit_sharing(&ws, &zs);
        let ch: F = hashers.extract_challenge(Party::Prover);
        commitments.push(hashers.hashes());

        let cache = crate::cache::Cache::<F>::new(&circuit, K, true);
        let mut round = round1(Round { xs, ys, z: None }, &zs, ch);
        let (mut hs, mut rands) = (vec![], vec![]);
        if nrounds > 0 {
            for i in 0..=nrounds {
                round = round_compress_start(
                    round,
                    K,
                    i == nrounds,
                    &cache,
                    &mut hashers,
                    &mut rands,
                    &mut hs,
                    &mut rngs,
                );
                let c: F = hashers.extract_challenge(Party::Prover);
                commitments.push(hashers.hashes());
                round = round_compress_finish(
                    round,
                    K,
                    i == nrounds,
                    &cache,
                    c,
                    &rands,
                    hs.last().unwrap(),
                );
            }
        }

        let output = OutputShares::new(round, output_share);
        let id = hashers.extract_unopened_party(Party::Prover, N);
        let proof = ProofSingle::<F, N>::new(
            output,
            OpenedPartiesShares::new(id, ws, zs, hs, rands, seeds),
            UnopenedParty::new(id, &commitments, hashers.hash_of_id(id)),
        );

        // The forged proof for this unsatisfiable circuit should not pass verification.
        let cache_v = crate::cache::Cache::<F>::new(&circuit, K, false);
        assert!(proof.verify(&circuit, K, &cache_v).is_err());
    }
}
