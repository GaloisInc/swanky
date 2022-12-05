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
use anyhow::anyhow;
use rayon::prelude::*;
use scuttlebutt::field::FiniteField;
use scuttlebutt::AesRng;
use simple_arith_circuit::Circuit;

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
        rng: &mut AesRng,
    ) -> Self {
        assert!(N.is_power_of_two() && N <= 256);
        assert_eq!(witness.len(), circuit.ninputs());
        assert_eq!(circuit.noutputs(), 1);
        let time = std::time::Instant::now();
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        log::debug!("Number of compression rounds = {nrounds}");
        let cache = Cache::new(circuit, compression_factor, true);
        // Each MPC-in-the-head repetition needs its own RNG, so we create the necessary RNGs here.
        let mut rngs: Vec<AesRng> = (0..repetitions).map(|_| rng.fork()).collect();
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
    ) -> anyhow::Result<()> {
        assert!(N.is_power_of_two() && N <= 256);
        assert_eq!(circuit.noutputs(), 1);
        if !crate::utils::validate_parameters::<F>(N, compression_factor, repetitions) {
            return Err(anyhow!("Invalid parameters: ({N}, {compression_factor}, {repetitions}) do not match acceptable settings"));
        }
        let time = std::time::Instant::now();
        let cache = Cache::new(circuit, compression_factor, false);
        if self.proofs.len() != repetitions {
            return Err(anyhow!("Invalid number of repetitions"));
        }
        // Use `rayon` to parallelize the MPC-in-the-head repetitions.
        let results: Vec<anyhow::Result<()>> = self
            .proofs
            .par_iter()
            .enumerate()
            .map(|(i, proof)| {
                let time_ = std::time::Instant::now();
                log::debug!("Checking proof #{}", i + 1);
                if let Err(e) = proof.verify(circuit, compression_factor, &cache) {
                    return Err(anyhow!("Proof #{} failed: {}", i + 1, e));
                }
                log::debug!("Verifying proof #{} succeeded.", i + 1);
                log::info!("Proof #{} verification time: {:?}", i + 1, time_.elapsed());
                Ok(())
            })
            .collect();
        log::info!("Verification time: {:?}", time.elapsed());
        if let Some(err) = results.into_iter().find_map(|r| r.err()) {
            Err(err)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::field::F64b;

    const N: usize = 16;
    const K: usize = 8;
    const T: usize = 40;

    macro_rules! test_serialization {
        ($modname: ident, $field: ty) => {
            mod $modname {
                use super::*;
                #[allow(unused_imports)]
                use proptest::prelude::*;
                use scuttlebutt::Block;

                fn any_seed() -> impl Strategy<Value = Block> {
                    any::<u128>().prop_map(|seed| Block::from(seed))
                }

                proptest! {
                #[test]
                fn serialize_bincode(seed in any_seed()) {
                    let mut rng = AesRng::from_seed(seed);
                    let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, AesRng>(10, 100, &mut rng);
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
}
