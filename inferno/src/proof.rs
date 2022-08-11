use crate::cache::Cache;
use crate::proof_single::{ProofSingle, ProverSingle};
use rayon::prelude::*;
use scuttlebutt::field::FiniteField;
use scuttlebutt::AesRng;
use simple_arith_circuit::Circuit;

/// The inferno proof.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Proof<F: FiniteField, const N: usize> {
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    proofs: Vec<ProofSingle<F, N>>,
}

impl<F: FiniteField, const N: usize> Proof<F, N> {
    /// Construct a proof for `circuit` with `witness`, using the provided compression factor and number of repetitions.
    ///
    /// `witness` must be of length equal to the number of inputs to `circuit`, and `circuit` must only
    /// contain one output wire.
    pub fn prove(
        circuit: &Circuit<F::PrimeField>,
        witness: &[F::PrimeField],
        compression_factor: usize,
        repetitions: usize,
        rng: &mut AesRng,
    ) -> Self {
        assert_eq!(witness.len(), circuit.ninputs());
        assert_eq!(circuit.noutputs(), 1);
        let time = std::time::Instant::now();
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        log::debug!("Number of compression rounds = {nrounds}");
        let cache = Cache::new(circuit, compression_factor, true);
        let mut rngs: Vec<AesRng> = (0..repetitions).map(|_| rng.fork()).collect();
        let proofs: Vec<ProofSingle<F, N>> = rngs
            .par_iter_mut()
            .enumerate()
            .map(|(i, rng)| {
                log::info!("Proof #{}", i + 1);
                let time_ = std::time::Instant::now();
                let mut prover =
                    ProverSingle::new(circuit, witness, compression_factor, nrounds, rng);
                let proof = prover.run(&cache);
                log::info!("Proof #{} time: {:?}", i + 1, time_.elapsed());
                proof
            })
            .collect();
        log::info!("Proof time: {:?}", time.elapsed());
        Self { proofs }
    }

    /// Verify that the proof on `circuit` is valid, for the given compression factor and number of repetitions.
    ///
    /// `circuit` must contain only one output wire.
    pub fn verify(
        &self,
        circuit: &Circuit<F::PrimeField>,
        compression_factor: usize,
        repetitions: usize,
    ) -> bool {
        assert_eq!(circuit.noutputs(), 1);
        let time = std::time::Instant::now();
        let cache = Cache::new(circuit, compression_factor, false);
        if self.proofs.len() != repetitions {
            log::debug!("Verify failed: Invalid number of repetitions");
            return false;
        }
        let result = self
            .proofs
            .par_iter()
            .enumerate()
            .map(|(i, proof)| {
                let time_ = std::time::Instant::now();
                log::debug!("Checking proof #{}", i + 1);
                if !proof.verify(circuit, compression_factor, &cache) {
                    log::debug!("Verifying proof #{} failed!", i + 1);
                    return false;
                }
                log::debug!("Verifying proof #{} succeeded.", i + 1);
                log::info!("Proof #{} verification time: {:?}", i + 1, time_.elapsed());
                true
            })
            .all(|r| r);
        log::info!("Verification time: {:?}", time.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::field::{F61p, F64b};

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
                    assert_eq!(proof.verify(&circuit, K, T), true);
                }
                }
            }
        };
    }

    test_serialization!(serialization_f61p, F61p);
    test_serialization!(test_serialization_f64b, F64b);
}
