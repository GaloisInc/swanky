use scuttlebutt::{field::FiniteField, AesRng};

use crate::{
    cache::Cache,
    hashers::Hashers,
    secretsharing::{LinearSharing, SecretSharing},
};

// The output of each compression round.
pub(crate) struct Round<S> {
    pub xs: Vec<S>,
    pub ys: Vec<S>,
    // The dot product of `xs` and `ys`, when we need it.
    // The value is `None` when starting a compression round,
    // and `Some` when ending a compression round.
    pub z: Option<S>,
}

// This round is shared between the prover and verifier.
pub(crate) fn round1<S: LinearSharing<F, N>, F: FiniteField, const N: usize>(
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

// This round is only run by the prover.
pub(crate) fn round_compress_start<F: FiniteField, const N: usize>(
    round: Round<SecretSharing<F, N>>,
    k: usize,          // The compression factor.
    final_round: bool, // If `true` then run `Π_CompressRand`.
    cache: &Cache<F>,
    hashers: &mut Hashers<N>,
    rands: &mut Vec<(SecretSharing<F, N>, SecretSharing<F, N>)>,
    hs: &mut Vec<Vec<SecretSharing<F, N>>>,
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
    hs.push(hshares);
    if final_round {
        *rands = rand_shares;
    }
    Round {
        xs: round.xs,
        ys: round.ys,
        z: None,
    }
}

// This round is shared between the prover and the verifier.
pub(crate) fn round_compress_finish<S: LinearSharing<F, N>, F: FiniteField, const N: usize>(
    input: Round<S>,
    compression_factor: usize,
    final_round: bool,
    cache: &Cache<F>,
    challenge: F,
    rands: &[(S, S)],
    hs: &[S],
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
