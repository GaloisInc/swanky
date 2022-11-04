//! Implements a single MPC-in-the-head iteration of the Limbo protocol.

use crate::{
    cache::Cache,
    circuit::CircuitEvaluator,
    secretsharing::{CorrectionSharing, LinearSharing, SecretSharing},
};
use anyhow::anyhow;
use blake3::{Hash, Hasher, OutputReader};
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
pub struct ProofSingle<F: FiniteField, const N: usize> {
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    output: OutputShares<F, N>,
    #[serde(bound = "")] // Needed due to https://github.com/rust-lang/rust/issues/41617
    shares: OpenedParties<F, N>,
    unopened: UnopenedParty,
}

impl<F: FiniteField, const N: usize> ProofSingle<F, N> {
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
pub struct OutputShares<F: FiniteField, const N: usize> {
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
    fn new(round: Round<SecretSharing<F, N>>, output: SecretSharing<F::PrimeField, N>) -> Self {
        Self {
            fs: round.xs.into_iter().map(|x| x.into()).collect(),
            gs: round.ys.into_iter().map(|y| y.into()).collect(),
            h: round.z.unwrap().into(),
            output: output.into(),
        }
    }

    // Verify that the prover output is valid. This involes the following checks:
    // 1. The `output` shares reconstruct to `1`.
    // 2. The `fs` and `gs` shares dot product to `h`.
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

    // Verify that the shares in `round` are valid for all parties except the party matching index `id`.
    fn verify_shares(
        &self,
        round: Round<CorrectionSharing<F, N>>,
        id: usize,
    ) -> anyhow::Result<()> {
        assert!(id < N);
        for (f, f_) in self.fs.iter().zip(round.xs.iter()) {
            if !f.check_equality(f_, id) {
                return Err(anyhow!("`f` shares not equal"));
            }
        }
        for (g, g_) in self.gs.iter().zip(round.ys.iter()) {
            if !g.check_equality(g_, id) {
                return Err(anyhow!("`g` shares not equal"));
            }
        }
        if !self.h.check_equality(&round.z.unwrap(), id) {
            return Err(anyhow!("`h` shares not equal"));
        }
        Ok(())
    }
}

// The secret shares of the parties opened as part of the verification check.
#[derive(Serialize, Deserialize)]
pub struct OpenedParties<F: FiniteField, const N: usize> {
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
    // Checks that the shares are valid for the given circuit and the given unopened party.
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
        hashers.hash_round0(&witness, &mults);
        let c = hashers.extract_challenge(Some((unopened.id, Hash::from(unopened.commitments[0]))));
        log::debug!("Challenge: {:?}", c);
        let (xs, ys) = circuit.eval_trace(&witness, &mults);
        let round0 = Round { xs, ys, z: None };
        let mut round = round1(&round0, &mults, c);
        if nrounds > 0 {
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
                    &round_,
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
                round_compress_finish(&round_, &self.rands, hs, c, compression_factor, true, cache);
        }
        let id = hashers.extract_unopened_party(Some((unopened.id, Hash::from(unopened.trace))), N);
        log::debug!("Party ID: {id}");
        if id != unopened.id {
            return Err(anyhow!("Incorrect party ID encountered"));
        }
        // Now check that `round` was computed correctly.
        output.verify_shares(round, id)
    }
}

/// Info necessary to "process" the unopened party when validating the proof.
#[derive(Serialize, Deserialize)]
pub struct UnopenedParty {
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

// The state of the prover for any given round of the protocol.
enum ProverSingleState<F: FiniteField, const N: usize> {
    Init(Round<SecretSharing<F::PrimeField, N>>),
    Next(Round<SecretSharing<F, N>>),
    Finished,
}

// The prover for a single execution of the Limbo protocol.
pub struct ProverSingle<F: FiniteField, const N: usize> {
    // The compression factor.
    k: usize,
    // The number of compression rounds.
    nrounds: usize,
    // What round are we on currently.
    niters: usize,
    // The hashers for each of the `N` MPC parties.
    hashers: Hashers<N>,
    // The shares of each MPC party.
    shares: PartyShares<F, N>,
    // What state of the protocol are we in.
    state: ProverSingleState<F, N>,
    // The "commitments" of each party at each step of the protocol.
    // In reality, these correspond to the hashes of that party's trace up to
    // the given point.
    commitments: Vec<[Hash; N]>,
    // The RNGs used for generating shares of each party.
    rngs: [AesRng; N],
}

impl<F: FiniteField, const N: usize> ProverSingle<F, N> {
    /// Start a new prover for `circuit` and `witness`, using the given compression factor.
    pub fn new(
        circuit: &Circuit<F::PrimeField>,
        witness: &[F::PrimeField],
        compression_factor: usize,
        nrounds: usize,
        rng: &mut AesRng,
    ) -> Self {
        let mut hashers = Hashers::new();
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
        let shares = PartyShares::new(ws, zs, output, seeds);
        let round0 = Round { xs, ys, z: None };
        Self {
            k: compression_factor,
            nrounds,
            niters: 0,
            hashers,
            shares,
            state: ProverSingleState::Init(round0),
            commitments: vec![],
            rngs,
        }
    }

    /// Run the prover.
    pub fn run(&mut self, cache: &Cache<F>) -> ProofSingle<F, N> {
        // Run the MPC protocol.
        let mut output = None;
        while output.is_none() {
            output = self.next(cache);
        }
        // The MPC protocol is complete. Now, collect the necessary information for constructing the proof.
        let output = output.unwrap(); // This `unwrap` will never fail.

        // Figure out which party will not be opened.
        let id = self.hashers.extract_unopened_party(None, N);
        log::debug!("Party ID: {}", id);
        // Gather info for the unopened party.
        let unopened = UnopenedParty::new(id, &self.commitments, self.hashers.hash_of_id(id));
        // Provide shares for all the opened parties.
        let shares = self.shares.extract(id);
        // And that's our proof!
        ProofSingle {
            output,
            shares,
            unopened,
        }
    }

    /// Run the next step of the proof. Upon proof completion, this outputs a
    /// `ProverSingleOutput` object containing the output to be sent to the verifier.
    /// Otherwise, it outputs `None`, meaning `next` should continue to be called.
    fn next(&mut self, cache: &Cache<F>) -> Option<OutputShares<F, N>> {
        // Figure out the challenge.
        let challenge = self.hashers.extract_challenge(None);
        log::debug!("Challenge: {:?}", challenge);
        // Store the current hashes of each party trace as commitments.
        self.commitments.push(self.hashers.hashes());
        let round = match &self.state {
            ProverSingleState::Init(round) => {
                let round = round1(round, &self.shares.mults, challenge);
                // This happens if the circuit has _no_ multiplication gates
                if self.niters == self.nrounds {
                    return self.finish(round);
                }
                round
            }
            ProverSingleState::Next(round) => {
                let round = round_compress_finish::<SecretSharing<F, N>, F, N>(
                    round,
                    &self.shares.rands,
                    self.shares.hs.last().unwrap(),
                    challenge,
                    self.k,
                    self.niters == self.nrounds,
                    cache,
                );
                if self.niters == self.nrounds {
                    return self.finish(round);
                }
                self.niters += 1;
                round
            }
            ProverSingleState::Finished => unreachable!("No more rounds to process"),
        };
        let round = self.round_compress_start(round, self.niters == self.nrounds, cache);
        self.state = ProverSingleState::Next(round);
        None
    }

    fn finish(&mut self, round: Round<SecretSharing<F, N>>) -> Option<OutputShares<F, N>> {
        self.state = ProverSingleState::Finished;
        Some(OutputShares::new(round, self.shares.output))
    }

    fn round_compress_start(
        &mut self,
        round: Round<SecretSharing<F, N>>,
        // If `true` then run `Π_CompressRand`.
        final_round: bool,
        cache: &Cache<F>,
    ) -> Round<SecretSharing<F, N>> {
        let dimension = (round.xs.len() as f32 / self.k as f32).ceil() as usize;
        log::debug!(
            "{}Compressing length {} vector by {} ⟶  {dimension}",
            if final_round { "[Final Round] " } else { "" },
            round.xs.len(),
            self.k
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
            hshares[i] = SecretSharing::<F, N>::new(c, &mut self.rngs);
            self.hashers.hash_sharing(&hshares[i]);
        }
        hshares[k - 1] =
            SecretSharing::<F, N>::new(round.z.unwrap().secret() - sum, &mut self.rngs);
        self.hashers.hash_sharing(&hshares[k - 1]);

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
                random = (
                    SecretSharing::random(&mut self.rngs),
                    SecretSharing::random(&mut self.rngs),
                );
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
            hshares[k + i] = SecretSharing::<F, N>::new(h_u, &mut self.rngs);
            self.hashers.hash_sharing(&hshares[k + i]);
        }
        self.shares.add_hs(hshares);
        if final_round {
            self.shares.set_rands(rand_shares);
        }
        Round {
            xs: round.xs,
            ys: round.ys,
            z: None,
        }
    }
}

// This round is shared between the prover and verifier, hence why it exists as a standalone function.
fn round1<S: LinearSharing<F, N>, F: FiniteField, const N: usize>(
    round0: &Round<S::SelfWithPrimeField>,
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
    input: &Round<S>,
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

    // Extracts the party trace from the various views collected during the
    // execution of a prover for all parties but the one specified by `id`.
    //
    // TODO: This should be `self` instead of `&self`.
    pub fn extract(&self, id: usize) -> OpenedParties<F, N> {
        assert!(id < N);
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
                let arr = h.extract(id);
                shares.push(arr);
            }
            hs.push(shares);
        }
        let mut rands = Vec::with_capacity(self.rands.len());
        for r in self.rands.iter() {
            let arr0 = r.0.extract(id);
            let arr1 = r.1.extract(id);
            rands.push((arr0, arr1));
        }
        let mut seeds = self.seeds;
        seeds[id] = 0u128;
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

// A collection of `N` `Hasher`s, one for each of the `N` parties in the MPC.
struct Hashers<const N: usize>([Hasher; N]);

impl<const N: usize> Hashers<N> {
    pub fn new() -> Self {
        let hashers = [(); N].map(|_| Hasher::new());
        Self(hashers)
    }

    // Construct a hash output from the hash of each party's trace.
    // If `unopened` is `None`, this corresponds to the prover.
    // In this case we simply combine the hashes of each party.
    // If `unopened` is `Some((id, com))`, we combine the hashes of each party
    // _except_ the party corresponding to `id`. In this case, we use `com` instead.
    fn output(&self, unopened: Option<(usize, Hash)>) -> OutputReader {
        let mut hasher = Hasher::new();
        let (unopened_id, unopened_hash) = match unopened {
            Some((id, hash)) => (id, *hash.as_bytes()),
            None => (usize::MAX, [0u8; 32]),
        };
        for (id, hasher_) in self.0.iter().enumerate() {
            if id == unopened_id {
                hasher.update(&unopened_hash);
            } else {
                hasher.update(hasher_.finalize().as_bytes());
            }
        }
        hasher.finalize_xof()
    }

    // Extract the ID of the party to _not_ open.
    pub fn extract_unopened_party(&self, unopened: Option<(usize, Hash)>, n: usize) -> usize {
        let mut output = self.output(unopened);
        let mut result = [0u8; 1];
        output.fill(&mut result);
        let id: usize = result[0] as usize;
        id % n
    }

    // Extract a challenge field element.
    pub fn extract_challenge<F: FiniteField>(&self, unopened: Option<(usize, Hash)>) -> F {
        let mut output = self.output(unopened);
        let mut result = [0u8; 16];
        output.fill(&mut result);
        F::from_uniform_bytes(&result)
    }

    // Extract the hash of the trace for the given `id`.
    pub fn hash_of_id(&self, id: usize) -> Hash {
        self.0[id].finalize()
    }

    // Extract the hashes of the traces of all parties.
    pub fn hashes(&self) -> [Hash; N] {
        self.0
            .iter()
            .map(|h| h.finalize())
            .collect::<Vec<Hash>>()
            .try_into()
            .unwrap() // This `unwrap` will never fail
    }

    #[inline]
    pub fn hash_sharing<S: LinearSharing<F, N>, F: FiniteField>(&mut self, share: &S) {
        share.hash(&mut self.0)
    }

    pub fn hash_round0<S: LinearSharing<F, N>, F: FiniteField>(&mut self, ws: &[S], zs: &[S]) {
        for w in ws.iter() {
            self.hash_sharing(w);
        }
        for z in zs.iter() {
            self.hash_sharing(z);
        }
    }

    fn hash_round<S: LinearSharing<F, N>, F: FiniteField>(&mut self, hs: &[S]) {
        for h in hs.iter() {
            h.hash(&mut self.0);
        }
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
                    let nrounds = crate::utils::nrounds(&circuit, K);
                    let mut prover = ProverSingle::<$field, N>::new(&circuit, &witness, K, nrounds, &mut rng);
                    let cache = crate::cache::Cache::new(&circuit, K, true);
                    let proof = prover.run(&cache);
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
