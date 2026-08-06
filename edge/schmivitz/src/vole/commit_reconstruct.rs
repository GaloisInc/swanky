/*!
Implementation of algorithms to commit, open and reconstruct VOLEs.
 *
 */
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::{Decom, Pdecom, commit, open, reconstruct};
use crate::vole::convert_to_vole::{convert_to_vole, convert_to_vole_verifier};
use crate::vole::crypto_primitives::{Chall3, Com, H1, H1_LENGTH, IV, Prg, Seed};
use generic_array::{GenericArray, arr, typenum::U16};
use rand::RngExt;
use rayon::iter::*;
use std::{sync::mpsc::channel, thread};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F2, F8b};
use swanky_serialization::CanonicalSerialize;

use super::consistency_check::HashConsistency;

/// Parameter used for padding for the security of the consistency check
pub(crate) const B: usize = 16;

/// Function mapping 8 booleans to [`u8`].
pub(crate) fn bools_to_u8(d: &[bool]) -> u8 {
    debug_assert_eq!(d.len(), 8);
    let mut r: u8 = 0;
    for (i, b) in d.iter().enumerate() {
        r |= if *b { 1u8 << i } else { 0u8 };
    }

    r
}

/// VOLE correction values.
#[derive(Clone, Default)]
pub(crate) struct Corrections([Vec<F2>; REPETITION_PARAM - 1]);

impl Corrections {
    pub(crate) fn length(&self) -> usize {
        let s = self.0[0].len();
        for v in self.0.iter() {
            assert_eq!(v.len(), s)
        }
        s
    }

    /// Convert corrections to associated bytes.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        // Corrections are a vector containing tau vectors of long size
        let how_many = self.0[0].len();
        let tau = self.0.len();
        let mut out = Vec::with_capacity((how_many * tau) / 8);

        let mut b = 0u8;
        let mut i = 0;
        for c in self.0.iter() {
            for bit in c.iter() {
                b |= if *bit == F2::ZERO { 0 } else { 1 << i };
                if i == 7 {
                    out.push(b);
                    b = 0u8;
                    i = 0;
                } else {
                    i += 1;
                }
            }
        }
        out
    }
}

/// hash the commitments coming from the small-domain VOLE
fn hash_commitments(com: &[Com]) -> Com {
    assert_eq!(com.len(), REPETITION_PARAM);
    let mut com_bytes = Vec::with_capacity(H1_LENGTH * REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        com_bytes.extend::<&[u8]>(com[i].as_ref());
    }
    H1::hash(&com_bytes).into()
}

/// VOLEs alongside their associated commitments.
///
/// This type is constructed in `FAEST.VOLECommit` (Figure 5.4 of the FAEST spec
/// v1.1).
pub(crate) struct VoleCommitment {
    /// Hash of the commitments from all the small domain VOLEs.
    pub(crate) h_com: Com,
    /// Decommitment from all the small domain VOLEs.
    pub(crate) decom: [Decom; REPETITION_PARAM],
    /// Correction values. These correspond to `c` in the Figure.
    pub(crate) corrections: Corrections,
    /// Random masks associated with VOLEs.
    pub(crate) u: Vec<F2>,
    /// Commitments associated to `u`. These are "packed" bit vectors.
    pub(crate) v: Vec<[F8b; REPETITION_PARAM]>,
}

impl VoleCommitment {
    /// Generate the VOLEs alongside associated commitments.
    ///
    /// This corresponds to Figure 5.4 of the FAEST spec (v1.1). It uses
    /// multithreading to improve performance.
    #[inline(never)]
    pub(crate) fn create(seed: Seed, iv: IV, l_hat: usize) -> VoleCommitment {
        let mut rng = Prg::new(seed, iv);
        let mut u: Vec<Vec<F2>> = Vec::with_capacity(REPETITION_PARAM);
        let mut v = Vec::with_capacity(REPETITION_PARAM);
        let mut decom: [Decom; REPETITION_PARAM] = Default::default();
        let mut com = Vec::with_capacity(REPETITION_PARAM);

        let t = std::time::Instant::now();

        // Without multithreading: this is > 5x slower than with multithreading
        // for i in 0..REPETITION_PARAM {
        //     let seed = rng.r#gen::<Seed>();
        //     let (com_i, decom_i, seeds) = commit(seed, iv, 8);
        //     let (u_i, v_i) = convert_to_vole(&seeds, iv, l_hat, true);
        //     com.push(com_i);
        //     decom[i] = decom_i;
        //     u.push(u_i);
        //     v.push(v_i)
        // }

        // With multithreading.
        // Lines 3-7.
        let handles: [_; REPETITION_PARAM] = core::array::from_fn(|_| {
            let seed = rng.random::<Seed>();
            thread::spawn(move || {
                // for smaller circuits the `commit/reconstruct` part is not negligible compared to the
                // `convert_to_vole` part, therefore it is more efficient to execute both in
                // threads
                let (com_i, decom_i, seeds) = commit(seed, iv, 8);
                let (u_i, v_i) = convert_to_vole(
                    seeds
                        .try_into()
                        .expect("depth in `commit` hardcoded to 8, so this should never fail"),
                    iv,
                    l_hat,
                    true,
                );
                (com_i, decom_i, u_i, v_i)
            })
        });

        for (i, handle) in handles.into_iter().enumerate() {
            let (com_i, decom_i, u_i, v_i) = handle.join().unwrap();
            com.push(com_i);
            decom[i] = decom_i;
            u.push(u_i);
            v.push(v_i);
        }

        log::info!(
            "multithreaded convert_to_vole prover running time: {:?}",
            t.elapsed()
        );
        // End multithreading

        // Lines 10-11: Compute the corrections `cᵢ`.
        let t = std::time::Instant::now();
        let u_0 = u[0].clone(); // TODO: opt transmute here
        let mut corrections: [Vec<F2>; REPETITION_PARAM - 1] = Default::default();
        for i in 1..REPETITION_PARAM {
            debug_assert_eq!(l_hat, u_0.len());
            let ci: Vec<F2> = (0..l_hat)
                .into_par_iter()
                .map(|j| u_0[j] + u[i][j])
                .collect();
            corrections[i - 1] = ci;
        }
        log::info!("corrections running time: {:?}", t.elapsed());

        // Line 8: Convert to a row-wise, fixed-size representation.
        let t = std::time::Instant::now();
        let v_out: Vec<[F8b; REPETITION_PARAM]> = (0..l_hat)
            .into_par_iter()
            .map(|i| core::array::from_fn(|tau| v[tau][i]))
            .collect();
        log::info!("pack to F8b running time: {:?}", t.elapsed());

        // Line 12: Hash the commitments.
        let h_com = hash_commitments(&com);

        Self {
            h_com,
            decom,
            corrections: Corrections(corrections),
            u: u_0,
            v: v_out,
        }
    }
}

/// Function to decompose a challenge into boolean values.
pub(crate) fn chal_dec(chal: &[u8], i: usize) -> Vec<bool> {
    //let mut dec = vec![];

    //assert!(dec.len() == REPETITION_PARAM);
    //let mut r = vec![false; 8];
    //r.copy_from_slice(&FIXED_CHALLENGE);
    //r
    let b = chal[i];
    let mut r = vec![false; 8];
    for i in 0..8 {
        r[i] = ((b >> i) & 1) != 0;
    }
    r
}

/// Function to open voles and return the associated partial decommitment.
///
/// This function implements steps 20-22 of Fig 8.2
pub(crate) fn vole_open(chal: &[u8], decom: &[Decom]) -> [Pdecom; REPETITION_PARAM] {
    let mut pdecom: [Pdecom; REPETITION_PARAM] = Default::default();
    for i in 0..REPETITION_PARAM {
        let delta_i = chal_dec(chal, i);
        let pdecom_i = open(&decom[i], delta_i);
        pdecom[i] = pdecom_i;
    }
    pdecom
}

/// Function to reconstruct voles from a challenge and partial decommitments.
///
/// This implements Figure 5.5 in FAEST spec v1.1. The parameter `k_b` in that
/// spec is always our [`parameters::VOLE_SIZE_PARAM`].
#[inline(never)]
pub(crate) fn vole_reconstruct(
    chal: &[u8], // bytes from fiat-shamir challenge
    pdecom: &[Pdecom],
    iv: IV,
    l_hat: usize,
) -> (Com, Vec<Vec<F8b>>) {
    assert_eq!(pdecom.len(), REPETITION_PARAM);
    assert_eq!(chal.len(), REPETITION_PARAM);
    let mut qs = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);

    // Without multithreading:
    /*
    for i in 0..REPETITION_PARAM {
        let delta = chal_dec(chal, i);
        let (com_i, seeds) = reconstruct(pdecom[i].clone(), delta.clone(), iv);
        com.push(com_i);
        let q_i = convert_to_vole_verifier(&seeds, iv, l_hat, bools_to_u8(&delta));
        qs.push(q_i);
    }
    */

    // With multithreading:
    let t = std::time::Instant::now();
    let mut txs = Vec::with_capacity(REPETITION_PARAM);
    let mut rxs = Vec::with_capacity(REPETITION_PARAM);
    for _ in 0..REPETITION_PARAM {
        let (tx, rx) = channel();
        txs.push(tx);
        rxs.push(rx);
    }
    let mut handles = Vec::new();

    for i in 0..REPETITION_PARAM {
        let delta = chal_dec(chal, i);
        let pdecom = pdecom[i].clone();

        let tx = txs[i].clone();
        let handle = thread::spawn(move || {
            // for smaller circuits the `commit/reconstruct` part is not negligeable compared to the
            // `convert_to_vole` part, therefore it is more efficient to execute both in
            // threads
            let (com_i, seeds) = reconstruct(pdecom, delta.clone(), iv);
            let q_i = convert_to_vole_verifier(
                seeds.try_into().unwrap(), // The depth is hardcoded to 8, so this will never fail.
                iv,
                l_hat,
                bools_to_u8(&delta),
            );
            tx.send((com_i, q_i)).unwrap();
        });
        handles.push(handle);
    }

    for i in 0..REPETITION_PARAM {
        let (com_i, q_i) = rxs[i].recv().unwrap();
        qs.push(q_i);
        com.push(com_i);
    }
    log::info!(
        "multithreaded convert_to_vole verifier running time: {:?}",
        t.elapsed()
    );
    // End multithreading

    // hash the commitments
    let h_com = hash_commitments(&com);

    (h_com, qs)
}

// Compute the secret key delta from a challenge
pub(crate) fn compute_secret_key(chall3: &Chall3) -> GenericArray<F8b, U16> {
    // compute the big delta
    (0..REPETITION_PARAM)
        .map(|tau| {
            let delta_i = chal_dec(chall3, tau);
            F8b::from_bytes(&arr![bools_to_u8(&delta_i)])
        })
        .collect::<Result<GenericArray<F8b, U16>, _>>()
        .unwrap()
}

/// This function applies corrections to the verifier part of voles `q` using a challenge.
///
/// This function implements Lines 7-14 of Figure 8.3 of the FAEST spec.
/// `how_many` must be $`\hat \ell = \ell + B + 2\lambda`$.
#[inline(never)]
pub(crate) fn apply_corrections_to_q(
    q: Vec<Vec<F8b>>,
    chall3: &Chall3,
    corrections: &Corrections,
    how_many: usize,
) -> Vec<[F8b; REPETITION_PARAM]> {
    // Dimensions of `q`: \tau x l_hat x r = 16 x l_hat x 8.
    debug_assert!(q.len() == REPETITION_PARAM && q[0].len() == how_many);

    // Q_0 is the same
    // Change Q_i with the corrections:
    // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
    // Q = (Q_0 ... Q_{tau-1})
    let mut qs = Vec::with_capacity(how_many);
    for _ in 0..how_many {
        qs.push([F8b::default(); REPETITION_PARAM]);
    }
    for pos in 0..how_many {
        qs[pos][0] = q[0][pos];
    }

    // Apply the corrections. This also transposes the output relative to `q`.
    for tau in 1..REPETITION_PARAM {
        // Get challenge, and convert bools into `F2`. The unwrap should be safe because `chal_dec`
        // is supposed to return an 8-bit decomposition.
        let delta: [F2; 8] = chal_dec(chall3, tau)
            .into_iter()
            .map(F2::from)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for pos in 0..how_many {
            let c_tau = corrections.0[tau - 1][pos];

            let delta_times_corr = delta.map(|d_i| d_i * c_tau);
            let delta_times_corr_f8b: F8b = F2::form_superfield(&delta_times_corr.into());

            qs[pos][tau] = q[tau][pos] + delta_times_corr_f8b;
        }
    }
    qs
}

/// This function combines a challenge with the hash of `u` to be used for the consistency check by the verifier.
///
/// This function implements lines 8-11 in Fig 8.3 in the FAEST spec.
#[inline(never)]
pub(crate) fn recompose_d(chall3: &Chall3, u_tilda: &HashConsistency) -> Vec<F2> {
    assert_eq!(u_tilda.len(), SECURITY_PARAM + B);
    let how_many = u_tilda.len();
    let mut qs = Vec::with_capacity(how_many * REPETITION_PARAM * 8);

    for i in 0..REPETITION_PARAM {
        // Length of this must be $r$ = `VOLE_SIZE_PARAM`.
        let delta = chal_dec(chall3, i);
        let delta_f2: Vec<_> = delta.iter().map(|b| F2::from(*b)).collect();
        for b in delta_f2 {
            for u in u_tilda.into_iter() {
                qs.push(b * u);
            }
        }
    }
    assert_eq!(qs.len(), how_many * REPETITION_PARAM * 8);

    qs
}

/// Extended witness padded to support the protocol: $`\ell + B + 2\lambda`$.
///
/// This function takes the size of the extended witness as input and returns
/// that many more elements necessary based on the parameters of the protocol.
pub(crate) fn l_hat(l: usize) -> usize {
    l + B + 2 * SECURITY_PARAM
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;

    use super::{
        VoleCommitment, apply_corrections_to_q, compute_secret_key, l_hat, vole_open,
        vole_reconstruct,
    };
    use crate::vole::crypto_primitives::H1;
    use crate::vole::functionality::compute_seed_iv;
    use rand::rng;
    use swanky_field::{FiniteRing, IsSubFieldOf};
    use swanky_field_binary::{F2, F8b, F128b};

    #[test]
    fn test_vole_commit_reconstruct() {
        let rng = &mut rng();
        let secret = repeat_with(|| F2::random(rng))
            .take(100)
            .collect::<Vec<F2>>();
        let pk = vec![1u8];

        let how_many = l_hat(1_000);

        let mu: H1 = H1::hash(&pk);
        let (r, iv) = compute_seed_iv(&secret, &mu);

        let VoleCommitment {
            h_com: _,
            decom,
            corrections,
            u,
            v,
        } = VoleCommitment::create(r, iv, how_many);

        let chall3 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let pdecom = vole_open(&chall3, &decom);

        let (_h_ver, q) = vole_reconstruct(&chall3, &pdecom, iv, how_many);

        // Change Q_i with the corrections:
        // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
        // Q = (Q_0 ... Q_{tau-1})
        let q_f128b = apply_corrections_to_q(q, &chall3, &corrections, how_many);

        // compute the big delta
        let big_delta = compute_secret_key(&chall3);
        let big_delta_f128b: F128b = F8b::form_superfield(&big_delta);

        for pos in 0..how_many {
            let v_f128b: F128b = F8b::form_superfield(&v[pos].into());
            assert_eq!(
                v_f128b + u[pos] * big_delta_f128b,
                F8b::form_superfield(&q_f128b[pos].into())
            );
        }
    }
}
