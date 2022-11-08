//! Implements a single MPC-in-the-head iteration of the Limbo protocol.

use crate::{
    cache::Cache,
    circuit::CircuitEvaluator,
    hashers::Hashers,
    secretsharing::{CorrectionSharing, LinearSharing, SecretSharing},
};
use anyhow::anyhow;
use blake3::Hash;
use rand::{Rng, SeedableRng};
use scuttlebutt::{field::FiniteField, AesRng, Block};
use scuttlebutt::{ring::FiniteRing, serialization::serde_vec};
use serde::{Deserialize, Serialize};
use simple_arith_circuit::Circuit;

// The output of each compression round.
struct Round<F> {
    xs: Vec<F>,
    ys: Vec<F>,
    // The dot product of `xs` and `ys`, when we need it.
    // The value is `None` when starting a compression round,
    // and `Some` when ending a compression round.
    z: Option<F>,
}

/// The proof for a single execution of the protocol. `N` denotes
/// the number of participants in the MPC.
///
/// A proof contains:
/// 1. The shares of the output of the prover
/// 2. The shares of the opened parties
/// 3. The info needed to "process" the unopened party
#[derive(Serialize, Deserialize)]
pub(crate) struct ProofSingle<F: FiniteField, const N: usize> {
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    output: OutputShares<F, N>,
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    shares: OpenedParties<F, N>,
    unopened: UnopenedParty,
}

impl<F: FiniteField, const N: usize> ProofSingle<F, N> {
    pub fn prove(
        circuit: &Circuit<F::PrimeField>,
        witness: &[F::PrimeField],
        compression_factor: usize,
        cache: &Cache<F>,
        rng: &mut AesRng,
    ) -> Self {
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        let mut hashers = Hashers::new();
        let mut commitments = vec![];

        // Construct RNGs for each party.
        let seeds: [u128; N] = (0..N)
            .map(|_| rng.gen::<u128>())
            .collect::<Vec<u128>>()
            .try_into()
            .unwrap(); // This `unwrap` will never fail.
        let mut rngs = seeds.map(|seed| AesRng::from_seed(Block::from(seed)));

        // Secret share the witness.
        let ws: Vec<SecretSharing<F::PrimeField, N>> = witness
            .iter()
            .map(|w| SecretSharing::<F::PrimeField, N>::new(*w, &mut rngs))
            .collect();

        // Compute the sharing of the circuit itself.
        let mut xs = Vec::with_capacity(circuit.nmuls());
        let mut ys = Vec::with_capacity(circuit.nmuls());
        let mut zs = Vec::with_capacity(circuit.nmuls());
        let output = circuit.eval_secret_sharing(&ws, &mut xs, &mut ys, &mut zs, &mut rngs);

        hashers.hash_round0(&ws, &zs);
        let challenge = Self::challenge(&mut hashers, &mut commitments);

        let mut shares = PartyShares::new(ws, zs, output, seeds);
        let round0 = Round { xs, ys, z: None };
        let mut round = round1(round0, &shares.mults, challenge);
        // If we have no multiplication gates, then we have no compression to do.
        if nrounds > 0 {
            for i in 0..=nrounds {
                round = Self::round_compress_start(
                    round,
                    compression_factor,
                    &mut hashers,
                    &mut shares,
                    i == nrounds,
                    cache,
                    &mut rngs,
                );
                let challenge = Self::challenge(&mut hashers, &mut commitments);
                round = round_compress_finish::<SecretSharing<F, N>, F, N>(
                    round,
                    &shares.rands,
                    shares.hs.last().unwrap(),
                    challenge,
                    compression_factor,
                    i == nrounds,
                    cache,
                );
            }
        }
        let output = OutputShares::new(round, shares.output);
        // Figure out which party will not be opened.
        let id = hashers.extract_unopened_party(None, N);
        log::debug!("Party ID: {}", id);
        // Gather info for the unopened party.
        let unopened = UnopenedParty::new(id, &commitments, hashers.hash_of_id(id));
        // Provide shares for all the opened parties.
        let shares = shares.extract(id);
        // And that's our proof!
        ProofSingle {
            output,
            shares,
            unopened,
        }
    }

    fn challenge(hashers: &mut Hashers<N>, commitments: &mut Vec<[Hash; N]>) -> F {
        let challenge = hashers.extract_challenge(None);
        log::debug!("Challenge: {:?}", challenge);
        commitments.push(hashers.hashes());
        challenge
    }

    // This round is only run by the prover.
    fn round_compress_start(
        round: Round<SecretSharing<F, N>>,
        k: usize, // The compression factor
        hashers: &mut Hashers<N>,
        shares: &mut PartyShares<F, N>,
        final_round: bool, // If `true` then run `Π_CompressRand`.
        cache: &Cache<F>,
        rngs: &mut [AesRng; N],
    ) -> Round<SecretSharing<F, N>> {
        let dimension = (round.xs.len() as f32 / k as f32).ceil() as usize;
        log::debug!(
            "{}Compressing length {} vector by {} ⟶  {dimension}",
            if final_round { "[Final Round] " } else { "" },
            round.xs.len(),
            k
        );
        let k = round.xs.chunks(dimension).count();

        // Build `f` and `g` polynomials according to `Π_Compress[Rand]`.
        log::debug!(
            "Defining {} dimension-{} vectors of degree-{} polynomials",
            k,
            dimension,
            k - 1
        );

        let nchunks = if final_round { k + 1 } else { k };
        let top = if final_round { 2 * k + 1 } else { 2 * k - 1 };

        // Construct `c` and `h` sharings according to Steps 2, 3, and 5.
        let mut sum = F::ZERO;
        let mut hshares = vec![SecretSharing::<F, N>::default(); top];
        for (i, (left, right)) in round
            .xs
            .chunks(dimension)
            .take(k - 1)
            .zip(round.ys.chunks(dimension).take(k - 1))
            .enumerate()
        {
            let c = SecretSharing::<F, N>::dot(left, right);
            sum += c;
            hshares[i] = SecretSharing::<F, N>::new(c, rngs);
            hashers.hash_sharing(&hshares[i]);
        }
        hshares[k - 1] = SecretSharing::<F, N>::new(round.z.unwrap().secret() - sum, rngs);
        hashers.hash_sharing(&hshares[k - 1]);

        let mut rand_shares = if final_round {
            Vec::with_capacity(dimension)
        } else {
            vec![]
        };
        let mut random = (SecretSharing::default(), SecretSharing::default());
        let mut dots = vec![F::ZERO; top - k];
        let mut f_i = vec![F::ZERO; nchunks];
        let mut g_i = vec![F::ZERO; nchunks];
        let newton_polys = cache.newton_polys.read();
        let newton_bases = cache.newton_bases.read();
        let poly = newton_polys.get(&nchunks).unwrap();
        let bases = newton_bases.get(&(k, final_round)).unwrap();
        for i in 0..dimension {
            if final_round {
                random = (SecretSharing::random(rngs), SecretSharing::random(rngs));
            }
            // Polynomial `f_i` is a degree `k-1` polynomial defined by the points `(j, x_i[j])`.
            for (j, chunk) in round.xs.chunks(dimension).enumerate() {
                f_i[j] = if i < chunk.len() {
                    chunk[i].secret()
                } else {
                    F::ZERO
                };
            }
            if final_round {
                f_i[k] = random.0.secret();
            }
            poly.interpolate_in_place(&mut f_i[0..nchunks]);
            // Polynomial `g_i` is a degree `k-1` polynomial defined by the points `(j, y_i[j])`.
            for (j, chunk) in round.ys.chunks(dimension).enumerate() {
                g_i[j] = if i < chunk.len() {
                    chunk[i].secret()
                } else {
                    F::ZERO
                };
            }
            if final_round {
                g_i[k] = random.1.secret();
            }
            poly.interpolate_in_place(&mut g_i[0..nchunks]);
            // Iteratively compute the dot product of `f_i(u)` and `g_i(u)`.
            for (j, basis) in bases.iter().enumerate() {
                dots[j] += poly.eval_with_basis_polynomial(basis, &f_i)
                    * poly.eval_with_basis_polynomial(basis, &g_i);
            }
            if final_round {
                rand_shares.push(random);
            }
        }
        for (i, h_u) in dots.into_iter().enumerate() {
            hshares[k + i] = SecretSharing::<F, N>::new(h_u, rngs);
            hashers.hash_sharing(&hshares[k + i]);
        }
        shares.add_hs(hshares);
        if final_round {
            shares.set_rands(rand_shares);
        }
        Round {
            xs: round.xs,
            ys: round.ys,
            z: None,
        }
    }

    /// Verify the proof. This checks that:
    /// 1. The outputs of the MPC parties are correct.
    /// 2. The shares of the opened parties are correct.
    pub fn verify(
        &self,
        circuit: &Circuit<F::PrimeField>,
        compression_factor: usize,
        cache: &Cache<F>,
    ) -> anyhow::Result<()> {
        self.output.verify().and(self.shares.verify(
            circuit,
            &self.output,
            &self.unopened,
            compression_factor,
            cache,
        ))
    }
}

/// The output shares of the prover. This output contains four pieces of information:
/// * `fs`, `gs`, and `h` correspond to the final dot product. For the proof to be valid
/// it needs to hold that `dot(fs, gs) = h`.
/// * `output` corresponds to the output value. For the proof to be valid it must hold that
/// `output = 1`.
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
    /// Construct an `OutputShares` object from the computations of a round
    /// of the MPC-in-the-head protocol and the output shares of the protocol
    /// execution.
    fn new(round: Round<SecretSharing<F, N>>, output: SecretSharing<F::PrimeField, N>) -> Self {
        Self {
            fs: round.xs.into_iter().map(|x| x.into()).collect(),
            gs: round.ys.into_iter().map(|y| y.into()).collect(),
            h: round.z.unwrap().into(),
            output: output.into(),
        }
    }

    /// Verify that the prover output is valid. This involes the following checks:
    /// 1. The `output` shares reconstruct to `1`.
    /// 2. The `fs` and `gs` shares dot product to `h`.
    pub fn verify(&self) -> anyhow::Result<()> {
        let output = self.output.reconstruct();
        if output != <F::PrimeField as FiniteRing>::ZERO {
            return Err(anyhow!("Output not equal to zero"));
        }
        let mut sum = F::ZERO;
        for (f, g) in self.fs.iter().zip(self.gs.iter()) {
            sum += f.reconstruct() * g.reconstruct();
        }
        if sum != self.h.reconstruct() {
            return Err(anyhow!("Dot product not equal to `h`"));
        }
        Ok(())
    }

    /// Verify that the shares in `round` are valid for all parties except
    /// the party matching index `exclude`.
    ///
    /// # Panics
    /// Panics if `exclude >= N`.
    fn verify_shares(
        &self,
        round: Round<CorrectionSharing<F, N>>,
        exclude: usize,
    ) -> anyhow::Result<()> {
        assert!(exclude < N);
        for (f, f_) in self.fs.iter().zip(round.xs.iter()) {
            if !f.check_equality(f_, exclude) {
                return Err(anyhow!("`f` shares not equal"));
            }
        }
        for (g, g_) in self.gs.iter().zip(round.ys.iter()) {
            if !g.check_equality(g_, exclude) {
                return Err(anyhow!("`g` shares not equal"));
            }
        }
        if !self.h.check_equality(&round.z.unwrap(), exclude) {
            return Err(anyhow!("`h` shares not equal"));
        }
        Ok(())
    }
}

// The secret shares of the parties opened as part of the verification check.
#[derive(Serialize, Deserialize)]
pub(crate) struct OpenedParties<F: FiniteField, const N: usize> {
    // The RNG seeds used for each party, with the seed of the unopened party
    // zero-ed out.
    // XXX: This is a `Vec<u128>` instead of a `[u128; N]` because deriving
    // `Deserialize` on `[u128; N]` is problematic.
    seeds: Vec<u128>,
    // The correction values for the witness
    #[serde(bound = "", with = "serde_vec")]
    witness: Vec<F::PrimeField>,
    // The correction values for the multiplication outputs
    #[serde(bound = "", with = "serde_vec")]
    mults: Vec<F::PrimeField>,
    #[serde(bound = "")]
    hs: Vec<Vec<CorrectionSharing<F, N>>>,
    #[serde(bound = "")]
    rands: Vec<(CorrectionSharing<F, N>, CorrectionSharing<F, N>)>,
}

impl<F: FiniteField, const N: usize> OpenedParties<F, N> {
    /// Checks that the shares are valid for the given circuit and the given
    /// unopened party.
    fn verify(
        &self,
        circuit: &Circuit<F::PrimeField>,
        output: &OutputShares<F, N>,
        unopened: &UnopenedParty,
        compression_factor: usize,
        cache: &Cache<F>,
    ) -> anyhow::Result<()> {
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        let mut rngs: [AesRng; N] = self
            .seeds
            .iter()
            .map(|seed| AesRng::from_seed(Block::from(*seed)))
            .collect::<Vec<AesRng>>()
            .try_into()
            .unwrap();
        let mut hashers = Hashers::<N>::new();
        // Reconstruct the witness from the correction values and rng seeds.
        let witness: Vec<CorrectionSharing<F::PrimeField, N>> = self
            .witness
            .iter()
            .map(|correction| {
                CorrectionSharing::<F::PrimeField, N>::from_rngs(*correction, &mut rngs)
            })
            .collect();
        // Reconstruct the multiplication values from the correction values and rng seeds.
        let mults: Vec<CorrectionSharing<F::PrimeField, N>> = self
            .mults
            .iter()
            .map(|correction| {
                CorrectionSharing::<F::PrimeField, N>::from_rngs(*correction, &mut rngs)
            })
            .collect();
        // Hash the first round to derive the initial Fiat-Shamir challenge.
        hashers.hash_round0(&witness, &mults);
        let c = hashers.extract_challenge(Some((unopened.id, Hash::from(unopened.commitments[0]))));
        log::debug!("Challenge: {:?}", c);
        // Compute the multiplication inputs from the reconstructed
        // witness and reconstructed multiplication outputs.
        let (xs, ys) = circuit.eval_trace(&witness, &mults);
        // Now let's validate that these multiplication inputs are correct!
        // We do this by running the protocol on these reconstructed values
        // and seeing whether we get the correct result at the end.
        let round0 = Round { xs, ys, z: None };
        let mut round = round1(round0, &mults, c);
        // If we have no multiplication gates, then we have no rounds, in which
        // case we don't need to do this processing. So only do it if we have more
        // than zero rounds.
        if nrounds > 0 {
            // Iterate through all but the last rounds, using the commitments
            // of the unopened parties to help compute the Fiat-Shamir derived
            // challenge.
            for (hs, com) in self
                .hs
                .iter()
                .take(nrounds)
                .zip(unopened.commitments.iter().skip(1))
            {
                let round_ = Round {
                    xs: round.xs,
                    ys: round.ys,
                    z: None,
                };
                hashers.hash_round(hs);
                let c = hashers.extract_challenge(Some((unopened.id, Hash::from(*com))));
                log::debug!("Challenge: {:?}", c);
                round = round_compress_finish(
                    round_,
                    &self.rands,
                    hs,
                    c,
                    compression_factor,
                    false,
                    cache,
                );
            }
            // Last round!
            let round_ = Round {
                xs: round.xs,
                ys: round.ys,
                z: None,
            };
            let hs = self.hs.last().unwrap();
            hashers.hash_round(hs);
            let c = hashers.extract_challenge(Some((
                unopened.id,
                Hash::from(*unopened.commitments.last().unwrap()),
            )));
            log::debug!("Challenge: {:?}", c);
            round =
                round_compress_finish(round_, &self.rands, hs, c, compression_factor, true, cache);
        }
        // Now we derive the unopened party ID again using Fiat-Shamir.
        let id = hashers.extract_unopened_party(Some((unopened.id, Hash::from(unopened.trace))), N);
        log::debug!("Party ID: {id}");
        if id != unopened.id {
            return Err(anyhow!("Incorrect party ID encountered"));
        }
        // Finally, check that `round` was computed correctly by verifying
        // that the resulting shares are valid.
        output.verify_shares(round, id)
    }
}

/// Info necessary to "process" the unopened party when validating the proof.
#[derive(Serialize, Deserialize)]
pub(crate) struct UnopenedParty {
    // The index of this party
    id: usize,
    // The commitments, for each round of the protocol, associated with this party.
    commitments: Vec<[u8; 32]>,
    // The hash of the full trace of this party. Whereas `commitments` above gives the
    // hash after each _round_ of the protocol, this gives the hash of the full trace.
    trace: [u8; 32],
}

impl UnopenedParty {
    pub fn new<const N: usize>(id: usize, commitments: &[[Hash; N]], hash: Hash) -> Self {
        let commitments: Vec<[u8; 32]> =
            commitments.iter().map(|com| *com[id].as_bytes()).collect();
        Self {
            id,
            commitments,
            trace: *hash.as_bytes(),
        }
    }
}

// This round is shared between the prover and verifier, hence why it exists as a standalone function.
fn round1<S: LinearSharing<F, N>, F: FiniteField, const N: usize>(
    round0: Round<S::SelfWithPrimeField>,
    mults: &[S::SelfWithPrimeField],
    challenge: F,
) -> Round<S> {
    // Lift the sharings into the superfield.
    let mut sum = S::default();
    let mut xs = vec![S::default(); round0.xs.len()];
    let mut ys = vec![S::default(); round0.ys.len()];
    let mut r = challenge;
    for (i, ((x, y), z)) in round0
        .xs
        .iter()
        .zip(round0.ys.iter())
        .zip(mults.iter())
        .enumerate()
    {
        sum += S::multiply_by_superfield(z, r);
        xs[i] = S::multiply_by_superfield(x, r);
        ys[i] = S::lift_into_superfield(y);
        r *= r;
    }
    Round {
        xs,
        ys,
        z: Some(sum),
    }
}

// This round is shared between the prover and verifier, hence why it exists as a standalone function.
fn round_compress_finish<S: LinearSharing<F, N>, F: FiniteField, const N: usize>(
    input: Round<S>,
    rands: &[(S, S)],
    hs: &[S],
    challenge: F,
    compression_factor: usize,
    final_round: bool,
    cache: &Cache<F>,
) -> Round<S> {
    let dimension = (input.xs.len() as f32 / compression_factor as f32).ceil() as usize; // `ℓ` from the paper
    let nchunks = input.xs.chunks(dimension).count();
    let nchunks = if final_round { nchunks + 1 } else { nchunks };
    let mut fs = vec![S::default(); dimension];
    let mut gs = vec![S::default(); dimension];
    let mut values = vec![S::default(); nchunks];
    let mut polynomial = Vec::with_capacity(2 * nchunks - 1);
    {
        let lock = cache.evaluators.read();
        let evaluator = lock.get(&nchunks).unwrap();
        evaluator.basis_polynomial(&cache.points[0..nchunks], challenge, &mut polynomial);
        for i in 0..dimension {
            for (j, chunk) in input.xs.chunks(dimension).enumerate() {
                values[j] = if i < chunk.len() {
                    chunk[i]
                } else {
                    S::default()
                };
            }
            if final_round {
                *values.last_mut().unwrap() = rands[i].0;
            }
            fs[i] = evaluator.eval_with_basis_polynomial(&values[0..nchunks], &polynomial);
            for (j, chunk) in input.ys.chunks(dimension).enumerate() {
                values[j] = if i < chunk.len() {
                    chunk[i]
                } else {
                    S::default()
                };
            }
            if final_round {
                *values.last_mut().unwrap() = rands[i].1;
            }
            gs[i] = evaluator.eval_with_basis_polynomial(&values[0..nchunks], &polynomial);
        }
    }
    debug_assert_eq!(hs.len(), 2 * nchunks - 1);
    let z = {
        let lock = cache.evaluators.read();
        let evaluator = lock.get(&(2 * nchunks - 1)).unwrap();
        evaluator.basis_polynomial(
            &cache.points[0..2 * nchunks - 1],
            challenge,
            &mut polynomial,
        );
        evaluator.eval_with_basis_polynomial(hs, &polynomial)
    };
    Round {
        xs: fs,
        ys: gs,
        z: Some(z),
    }
}

// The secret shares for the protocol execution.
struct PartyShares<F: FiniteField, const N: usize> {
    witness: Vec<SecretSharing<F::PrimeField, N>>,
    mults: Vec<SecretSharing<F::PrimeField, N>>,
    hs: Vec<Vec<SecretSharing<F, N>>>,
    rands: Vec<(SecretSharing<F, N>, SecretSharing<F, N>)>,
    output: SecretSharing<F::PrimeField, N>,
    seeds: [u128; N],
}

impl<F: FiniteField, const N: usize> PartyShares<F, N> {
    pub fn new(
        witness: Vec<SecretSharing<F::PrimeField, N>>,
        mults: Vec<SecretSharing<F::PrimeField, N>>,
        output: SecretSharing<F::PrimeField, N>,
        seeds: [u128; N],
    ) -> Self {
        Self {
            witness,
            mults,
            output,
            hs: vec![],
            rands: vec![],
            seeds,
        }
    }

    /// Extracts the party trace from the various views collected during the
    /// execution of a prover for all parties but the one specified by `exclude`.
    // TODO: This should be `self` instead of `&self`.
    pub fn extract(&self, exclude: usize) -> OpenedParties<F, N> {
        assert!(exclude < N);
        let mut witness = Vec::with_capacity(self.witness.len());
        for w in self.witness.iter() {
            witness.push(w.correction());
        }
        let mut mults = Vec::with_capacity(self.mults.len());
        for m in self.mults.iter() {
            mults.push(m.correction());
        }
        let mut hs = Vec::with_capacity(self.hs.len());
        for hshares in self.hs.iter() {
            let mut shares = Vec::with_capacity(hshares.len());
            for h in hshares.iter() {
                let arr = h.extract(exclude);
                shares.push(arr);
            }
            hs.push(shares);
        }
        let mut rands = Vec::with_capacity(self.rands.len());
        for r in self.rands.iter() {
            let arr0 = r.0.extract(exclude);
            let arr1 = r.1.extract(exclude);
            rands.push((arr0, arr1));
        }
        let mut seeds = self.seeds;
        seeds[exclude] = 0u128;
        OpenedParties {
            witness,
            mults,
            hs,
            rands,
            seeds: seeds.to_vec(),
        }
    }

    pub fn add_hs(&mut self, hs: Vec<SecretSharing<F, N>>) {
        self.hs.push(hs);
    }

    pub fn set_rands(&mut self, rands: Vec<(SecretSharing<F, N>, SecretSharing<F, N>)>) {
        self.rands = rands;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::field::{F61p, F64b};

    const N: usize = 16;
    const K: usize = 8;

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
                    let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<<$field as FiniteField>::PrimeField, AesRng>(10, 1000, &mut rng);
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

    test_serialization!(serialization_f61p, F61p);
    test_serialization!(test_serialization_f64b, F64b);
}
