//! Implements a single MPC-in-the-head iteration of the Limbo protocol.

use crate::{
    cache::Cache,
    circuit::CircuitEvaluator,
    hashers::{Hashers, Party},
    round::{Round, round_compress_finish, round_compress_start, round1},
    secretsharing::{CorrectionSharing, LinearSharing, SecretSharing},
};
use blake3::Hash;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use simple_arith_circuit::Circuit;
use swanky_error::{ErrorKind, Result, ensure};
use swanky_field::FiniteField;
use swanky_field::FiniteRing;
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

/// The proof for a single execution of the protocol. `N` denotes
/// the number of participants in the MPC.
///
/// A proof contains:
/// 1. The shares of the output of the prover;
/// 2. The shares of the opened parties; and
/// 3. The info needed for the verifier to "process" the unopened party.
#[derive(Serialize, Deserialize)]
pub(crate) struct ProofSingle<F: FiniteField, const N: usize> {
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    output: OutputShares<F, N>,
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    shares: OpenedPartiesShares<F, N>,
    unopened: UnopenedParty,
}

impl<F: FiniteField, const N: usize> ProofSingle<F, N> {
    #[cfg(test)]
    /// Create a new [`ProofSingle`] object from a set of output shares, party
    /// shares, and an unopened party ID.
    pub(crate) fn new(
        output: OutputShares<F, N>,
        shares: OpenedPartiesShares<F, N>,
        unopened: UnopenedParty,
    ) -> Self {
        Self {
            output,
            shares,
            unopened,
        }
    }

    /// Generate a proof that `circuit(witness) = 0`.
    pub fn prove(
        circuit: &Circuit<F::PrimeField>,
        witness: &[F::PrimeField],
        compression_factor: usize,
        cache: &Cache<F>,
        rng: &mut SwankyRng,
    ) -> Self {
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        let nmuls = circuit.nmuls();
        let mut hashers = Hashers::new();
        let mut commitments = Vec::with_capacity(nrounds + 2);

        // Construct RNGs for each party.
        let seeds: [u128; N] = (0..N)
            .map(|_| rng.random::<u128>())
            .collect::<Vec<u128>>()
            .try_into()
            .unwrap(); // This `unwrap` will never fail.
        let mut rngs = seeds.map(|seed| SwankyRng::from_seed(U8x16::from(seed)));

        // Secret share the witness.
        let ws: Vec<SecretSharing<F::PrimeField, N>> = witness
            .iter()
            .map(|w| SecretSharing::<F::PrimeField, N>::new(*w, &mut rngs))
            .collect();

        // Compute the sharing of the circuit itself.
        let mut xs = Vec::with_capacity(nmuls);
        let mut ys = Vec::with_capacity(nmuls);
        let mut zs = Vec::with_capacity(nmuls);
        let output = circuit.eval_secret_sharing(&ws, &mut xs, &mut ys, &mut zs, &mut rngs);
        hashers.hash_circuit_sharing(&ws, &zs);
        let challenge = Self::prover_challenge(&mut hashers, &mut commitments);
        let mut rands = vec![];
        let mut hs = vec![];

        // Run the protocol: Start by lifting the initial sharings into their extension field and then
        // iteratively compress the multiplication check.
        let round0 = Round { xs, ys, z: None };
        let mut round = round1(round0, &zs, challenge);
        // If we have no multiplication gates, then we have no compression to do.
        if nrounds > 0 {
            for i in 0..=nrounds {
                round = round_compress_start::<F, N>(
                    round,
                    compression_factor,
                    i == nrounds,
                    cache,
                    &mut hashers,
                    &mut rands,
                    &mut hs,
                    &mut rngs,
                );
                let challenge = Self::prover_challenge(&mut hashers, &mut commitments);
                round = round_compress_finish::<SecretSharing<F, N>, F, N>(
                    round,
                    compression_factor,
                    i == nrounds,
                    cache,
                    challenge,
                    &rands,
                    hs.last().unwrap(),
                );
            }
        }
        let output = OutputShares::new(round, output);
        let id = hashers.extract_unopened_party(Party::Prover, N);
        log::debug!("Party ID: {}", id);
        let unopened = UnopenedParty::new(id, &commitments, hashers.hash_of_id(id));
        let shares = OpenedPartiesShares::<F, N>::new(id, ws, zs, hs, rands, seeds);
        ProofSingle {
            output,
            shares,
            unopened,
        }
    }

    fn prover_challenge(hashers: &mut Hashers<N>, commitments: &mut Vec<[Hash; N]>) -> F {
        let challenge = hashers.extract_challenge(Party::Prover);
        log::debug!("Challenge: {:?}", challenge);
        commitments.push(hashers.hashes());
        challenge
    }

    /// Verify the proof. This checks that:
    /// 1. The outputs of the MPC parties are correct.
    /// 2. The shares of the opened parties are correct. Checking this requires
    ///    re-running (most of) the protocol and validating that the trace of each
    ///    opened party is valid.
    pub fn verify(
        &self,
        circuit: &Circuit<F::PrimeField>,
        compression_factor: usize,
        cache: &Cache<F>,
    ) -> Result<()> {
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        let mut hashers = Hashers::<N>::new();

        let mut rngs = self.shares.reconstruct_rngs();
        let witness = self.shares.reconstruct_witness(&mut rngs);
        let mults = self.shares.reconstruct_mults(&mut rngs);

        // Hash the first round to derive the initial Fiat-Shamir challenge.
        hashers.hash_circuit_sharing(&witness, &mults);
        let challenge = hashers.extract_challenge(Party::Verifier((
            self.unopened.id,
            Hash::from(self.unopened.commitments[0]),
        )));
        log::debug!("Challenge: {:?}", challenge);
        // Compute the multiplication inputs from the reconstructed
        // witness and reconstructed multiplication outputs.
        let (xs, ys, output) = circuit.eval_trace(&witness, &mults);
        // Now let's validate that these multiplication inputs are correct!
        // We do this by running the protocol on these reconstructed values
        // and seeing whether we get the correct result at the end.
        let round0 = Round { xs, ys, z: None };
        let mut round = round1(round0, &mults, challenge);
        // If we have no multiplication gates, then we have no rounds, in which
        // case we don't need to do this processing. So only do it if we have more
        // than zero rounds.
        if nrounds > 0 {
            // Iterate through all but the last round, using the commitments
            // of the unopened parties to help compute the Fiat-Shamir derived
            // challenge.
            for (i, (hs, com)) in self
                .shares
                .hs
                .iter()
                .zip(self.unopened.commitments.iter().skip(1))
                .enumerate()
            {
                round = Round {
                    xs: round.xs,
                    ys: round.ys,
                    z: None,
                };
                hashers.hash_round(hs);
                let challenge = hashers
                    .extract_challenge(Party::Verifier((self.unopened.id, Hash::from(*com))));
                log::debug!("Challenge: {:?}", challenge);
                round = round_compress_finish(
                    round,
                    compression_factor,
                    i == nrounds,
                    cache,
                    challenge,
                    &self.shares.rands,
                    hs,
                );
            }
        }
        let id = hashers.extract_unopened_party(
            Party::Verifier((self.unopened.id, Hash::from(self.unopened.final_commitment))),
            N,
        );
        log::debug!("Party ID: {id}");
        // Check that the unopened party is extracted is the right one.
        self.unopened.verify_id(id)?;
        // Check that the last round was computed correctly by verifying
        // that they match the output shares.
        self.output.verify_last_round(round, id)?;
        // Finally, check that the output shares are valid.
        self.output.verify(output, id)?;
        Ok(())
    }
}

/// The output shares of the prover. This output contains four pieces of information:
/// * `fs`, `gs`, and `h` correspond to the final dot product. For the proof to be valid
///   it needs to hold that `dot(fs, gs) = h`.
/// * `output` corresponds to the output value. For the proof to be valid it must hold that
///   `output = 1`.
///
/// All four of these pieces are provided in shared form, as they correspond to the values of
/// each party in the MPC computation.
#[derive(Serialize, Deserialize)]
pub(crate) struct OutputShares<F: FiniteField, const N: usize> {
    // TODO: We can make these serialize smaller by doing a manual vector serialization.
    #[serde(bound = "")]
    fs: Vec<CorrectionSharing<F, N>>,
    #[serde(bound = "")]
    gs: Vec<CorrectionSharing<F, N>>,
    #[serde(bound = "")]
    h: CorrectionSharing<F, N>,
    #[serde(bound = "")]
    output: CorrectionSharing<F::PrimeField, N>,
}

impl<F: FiniteField, const N: usize> OutputShares<F, N> {
    /// Construct an `OutputShares` object from the computations of the final round
    /// of the MPC-in-the-head protocol and the output shares of the protocol
    /// execution.
    pub(crate) fn new(
        round: Round<SecretSharing<F, N>>,
        output: SecretSharing<F::PrimeField, N>,
    ) -> Self {
        Self {
            fs: round.xs.into_iter().map(|x| x.into()).collect(),
            gs: round.ys.into_iter().map(|y| y.into()).collect(),
            h: round.z.unwrap().into(),
            output: output.into(),
        }
    }

    /// Verify that the prover output is valid. This involves the following checks:
    /// 1. The `output` shares reconstruct to `0`.
    /// 2. The `fs` and `gs` shares dot product to `h`.
    /// 3. The output matches the computed output from circuit evaluation.
    pub fn verify(
        &self,
        computed_output: CorrectionSharing<F::PrimeField, N>,
        exclude: usize,
    ) -> Result<()> {
        let output = self.output.reconstruct();
        ensure!(
            output == <F::PrimeField as FiniteRing>::ZERO,
            ErrorKind::OtherError,
            "Output not equal to zero"
        );
        let mut sum = F::ZERO;
        for (f, g) in self.fs.iter().zip(self.gs.iter()) {
            sum += f.reconstruct() * g.reconstruct();
        }
        ensure!(
            sum == self.h.reconstruct(),
            ErrorKind::OtherError,
            "Dot product not equal to `h`"
        );
        ensure!(
            self.output.check_equality(&computed_output, exclude),
            ErrorKind::OtherError,
            "Output shares not equal to computed output shares"
        );
        Ok(())
    }

    /// Verify that the shares in `round` are valid for all parties except
    /// the party matching index `exclude`.
    ///
    /// # Panics
    /// Panics if `exclude >= N`.
    fn verify_last_round(
        &self,
        round: Round<CorrectionSharing<F, N>>,
        exclude: usize,
    ) -> Result<()> {
        assert!(exclude < N);
        for (f, f_) in self.fs.iter().zip(round.xs.iter()) {
            ensure!(
                f.check_equality(f_, exclude),
                ErrorKind::OtherError,
                "`f` shares not equal"
            );
        }
        for (g, g_) in self.gs.iter().zip(round.ys.iter()) {
            ensure!(
                g.check_equality(g_, exclude),
                ErrorKind::OtherError,
                "`g` shares not equal"
            );
        }
        ensure!(
            self.h.check_equality(&round.z.unwrap(), exclude),
            ErrorKind::OtherError,
            "`h` shares not equal"
        );
        Ok(())
    }
}

// The secret shares of the parties opened as part of the verification check.
#[derive(Serialize, Deserialize)]
pub(crate) struct OpenedPartiesShares<F: FiniteField, const N: usize> {
    // The RNG seeds used for each party, with the seed of the unopened party
    // zero-ed out.
    // XXX: This is a `Vec<u128>` instead of a `[u128; N]` because deriving
    // `Deserialize` on `[u128; N]` is problematic.
    seeds: Vec<u128>,
    // The correction values for the witness
    witness: Vec<F::PrimeField>,
    // The correction values for the multiplication outputs
    mults: Vec<F::PrimeField>,
    #[serde(bound = "")]
    hs: Vec<Vec<CorrectionSharing<F, N>>>,
    #[serde(bound = "")]
    rands: Vec<(CorrectionSharing<F, N>, CorrectionSharing<F, N>)>,
}

impl<F: FiniteField, const N: usize> OpenedPartiesShares<F, N> {
    /// Extracts the party trace from the various views collected during the
    /// execution of a prover for all parties but the one specified by `exclude`.
    pub fn new(
        exclude: usize,
        witness: Vec<SecretSharing<F::PrimeField, N>>,
        mults: Vec<SecretSharing<F::PrimeField, N>>,
        hs: Vec<Vec<SecretSharing<F, N>>>,
        rands: Vec<(SecretSharing<F, N>, SecretSharing<F, N>)>,
        mut seeds: [u128; N],
    ) -> Self {
        assert!(exclude < N);
        let mut witness_ = Vec::with_capacity(witness.len());
        for w in witness.iter() {
            witness_.push(w.correction());
        }
        let mut mults_ = Vec::with_capacity(mults.len());
        for m in mults.iter() {
            mults_.push(m.correction());
        }
        let mut hs_ = Vec::with_capacity(hs.len());
        for hshares in hs.iter() {
            let mut shares = Vec::with_capacity(hshares.len());
            for h in hshares.iter() {
                let arr = h.extract(exclude);
                shares.push(arr);
            }
            hs_.push(shares);
        }
        let mut rands_ = Vec::with_capacity(rands.len());
        for r in rands.iter() {
            let arr0 = r.0.extract(exclude);
            let arr1 = r.1.extract(exclude);
            rands_.push((arr0, arr1));
        }
        seeds[exclude] = 0u128;
        Self {
            witness: witness_,
            mults: mults_,
            hs: hs_,
            rands: rands_,
            seeds: seeds.to_vec(),
        }
    }

    pub fn reconstruct_rngs(&self) -> [SwankyRng; N] {
        self.seeds
            .iter()
            .map(|seed| SwankyRng::from_seed(U8x16::from(*seed)))
            .collect::<Vec<SwankyRng>>()
            .try_into()
            .unwrap() // This `unwrap` will never fail
    }

    pub fn reconstruct_witness(
        &self,
        rngs: &mut [SwankyRng; N],
    ) -> Vec<CorrectionSharing<F::PrimeField, N>> {
        Self::reconstruct(&self.witness, rngs)
    }

    pub fn reconstruct_mults(
        &self,
        rngs: &mut [SwankyRng; N],
    ) -> Vec<CorrectionSharing<F::PrimeField, N>> {
        Self::reconstruct(&self.mults, rngs)
    }

    fn reconstruct(
        corrections: &[F::PrimeField],
        rngs: &mut [SwankyRng; N],
    ) -> Vec<CorrectionSharing<F::PrimeField, N>> {
        corrections
            .iter()
            .map(|correction| CorrectionSharing::<F::PrimeField, N>::from_rngs(*correction, rngs))
            .collect()
    }
}

/// Info necessary to "process" the unopened party when validating the proof.
#[derive(Serialize, Deserialize)]
pub(crate) struct UnopenedParty {
    // The index of this party.
    id: usize,
    // The commitments, for each round of the protocol, associated with this party.
    commitments: Vec<[u8; 32]>,
    // The hash of the full trace of this party. Whereas `commitments` above gives the
    // hash after each _round_ of the protocol, this gives the hash of the full trace.
    final_commitment: [u8; 32],
}

impl UnopenedParty {
    pub fn new<const N: usize>(id: usize, commitments: &[[Hash; N]], hash: Hash) -> Self {
        let commitments: Vec<[u8; 32]> =
            commitments.iter().map(|com| *com[id].as_bytes()).collect();
        Self {
            id,
            commitments,
            final_commitment: *hash.as_bytes(),
        }
    }

    pub fn verify_id(&self, id: usize) -> Result<()> {
        ensure!(
            id == self.id,
            ErrorKind::OtherError,
            "Incorrect party ID encountered"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_field_binary::F64b;
    use swanky_field_ff_primes::F128p;

    const N: usize = 16;
    const K: usize = 8;

    macro_rules! test_serialization {
        ($modname: ident, $field: ty) => {
            mod $modname {
                use super::*;
                #[allow(unused_imports)]
                use proptest::prelude::*;
                use vectoreyes::U8x16;

                fn any_seed() -> impl Strategy<Value = U8x16> {
                    any::<u128>().prop_map(|seed| U8x16::from(seed))
                }

                proptest! {
                #[test]
                fn serialize_bincode(seed in any_seed()) {
                    let mut rng = SwankyRng::from_seed(seed);
                    let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, SwankyRng>(10, 1000, &mut rng);
                    let cache = crate::cache::Cache::new(&circuit, K, true);
                    let proof = ProofSingle::<$field, N>::prove(&circuit, &witness, K, &cache, &mut rng);
                    let serialized = bincode::serialize(&proof).unwrap();
                    let proof: ProofSingle<$field, N> = bincode::deserialize(&serialized).unwrap();
                    let cache = crate::cache::Cache::new(&circuit, K, false);
                    assert!(proof.verify(&circuit, K, &cache).is_ok());
                }
                }
            }
        };
    }

    test_serialization!(serialization_f128p, F128p);
    test_serialization!(test_serialization_f64b, F64b);

    // See GitHub Issue #43.
    //
    // Thanks to @rot256 for pointing this out!
    #[test]
    fn poc_check_equality_ignores_correction() {
        use simple_arith_circuit::{Circuit, Op};
        use swanky_field::FiniteRing;
        use swanky_field_ff_primes::F128p;

        type F = F128p;

        let mut rng = SwankyRng::new();

        // unsat. circuit: output = 1 regardless of input.
        let circuit: Circuit<F> = Circuit::new(1, 1, vec![Op::Constant(F::ONE)]);
        let fake_witness = vec![F::random(&mut rng)];

        // honest (unsat.) proof, internally consistent, but output.reconstruct() = 1.
        let cache_p = crate::cache::Cache::new(&circuit, K, true);
        let mut proof = ProofSingle::<F, N>::prove(&circuit, &fake_witness, K, &cache_p, &mut rng);

        // Confirm the output is non-zero.
        assert_ne!(proof.output.output.reconstruct(), F::ZERO);

        // Confirm the proof fails to verify.
        let cache_v = crate::cache::Cache::new(&circuit, K, false);
        assert!(proof.verify(&circuit, K, &cache_v).is_err());

        // set correction so output.reconstruct() = 0.
        let share_sum: F = proof.output.output.shares.into_iter().sum();
        proof.output.output.correction = F::ZERO - share_sum;

        // Check that proof verification continues to fail.
        assert!(proof.verify(&circuit, K, &cache_v).is_err());
    }

    // See GitHub Issue #43.
    //
    // Thanks to @rot256 for pointing this out!
    #[test]
    fn ensure_dot_product_checked() {
        use swanky_field::FiniteRing;
        use swanky_field_ff_primes::F128p;

        type F = F128p;

        let mut rng = SwankyRng::new();

        // unsat. circuit: output = 1 regardless of input.
        let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<
            F,
            SwankyRng,
        >(10, 1000, &mut rng);

        let cache_p = crate::cache::Cache::new(&circuit, K, true);
        let mut proof = ProofSingle::<F, N>::prove(&circuit, &witness, K, &cache_p, &mut rng);

        let cache_v = crate::cache::Cache::new(&circuit, K, false);
        assert!(proof.verify(&circuit, K, &cache_v).is_ok());

        for i in 0..proof.output.fs.len() {
            // Change the share of the unopened party in `fs` to force the dot product to fail.
            proof.output.fs[i].shares[proof.unopened.id] += F::ONE;

            // Confirm the proof fails to verify.
            assert!(proof.verify(&circuit, K, &cache_v).is_err());

            // Change the share back for the next iteration.
            proof.output.fs[i].shares[proof.unopened.id] -= F::ONE;
        }

        for i in 0..proof.output.gs.len() {
            // Change the share of the unopened party in `gs` to force the dot product to fail.
            proof.output.gs[i].shares[proof.unopened.id] += F::ONE;

            // Confirm the proof fails to verify.
            assert!(proof.verify(&circuit, K, &cache_v).is_err());

            // Change the share back for the next iteration.
            proof.output.gs[i].shares[proof.unopened.id] -= F::ONE;
        }

        // Change the share of the unopened party in `h` to force the dot
        // product to fail.
        proof.output.h.shares[proof.unopened.id] += F::ONE;
        // Confirm the proof fails to verify.
        assert!(proof.verify(&circuit, K, &cache_v).is_err());
    }
}
