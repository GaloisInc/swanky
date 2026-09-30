//! Implementation of the core VOLE protocol.
//!
//! The implementation is based on v1.1 of the FAEST spec[^1].
//!
//! [^1]: <https://faest.info/faest-spec-v1.1.pdf>
#![allow(clippy::needless_range_loop)]
use std::time::Instant;

use crate::parameters::{
    FLambda, Params, RepetitionParam, SecurityParam, SecurityParamBytes, SecurityParamPadded, Xof,
};
use crate::vole::AsSecretBytes;
use crate::vole::DecommitmentSerde;
use crate::vole::all_but_one_vc::{Decom, Pdecom};
use crate::vole::commit_reconstruct::{
    Corrections, VoleCommitment, apply_corrections_to_q, compute_secret_key, l_hat, recompose_d,
    vole_open, vole_reconstruct,
};
use crate::vole::consistency_check::{HashConsistency, VoleHasher};
use crate::vole::crypto_primitives::{Chall1, Chall3, Com, H1, H3, IV, Seed, h2_chall1};
use crate::vole::lift;
use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;
use rayon::prelude::*;
use sha3::digest::Update;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F8b};

#[cfg(test)]
use crate::vole::crypto_primitives::{Chall2, h2_chall3};

/// Compute a seed and initialization vection from secret key and hash of
/// statement to prove.
///
/// NOTE: `mu` is coming from the FAEST spec but expected to change when doing
/// more general circuits/polynomials. It's supposed to be a representation
/// of the public components of the computation.
pub(crate) fn compute_seed_iv<P: Params, Secret: AsSecretBytes>(
    secret: &Secret,
    mu: &H1<P>,
) -> (Seed<P>, IV) {
    let mut hasher = Xof::<P>::default();

    hasher.update(secret.as_bytes().as_ref());
    hasher.update(mu.as_ref());
    let r_iv: H3<P> = H3::from_xof(hasher);

    // Split hash digest into `r` and `iv`. These unwraps are safe because the
    // lengths are fixed.
    let (r_slice, iv_slice) = r_iv.as_ref().split_at(SecurityParamBytes::<P>::USIZE);
    let r = r_slice.try_into().unwrap();
    let iv = iv_slice.try_into().unwrap();
    (r, iv)
}

/// Compute first challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
pub(crate) fn compute_chall_1<P: Params>(
    mu: &H1<P>,
    h_com: &Com<P>,
    corrections: &Corrections<P>,
    iv: &IV,
) -> Chall1<P> {
    h2_chall1(mu, h_com, corrections, iv)
}

/// Compute third challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
#[cfg(test)]
pub(crate) fn compute_chall_3<P: Params>(
    chall2: &Chall2<P>,
    a_tilda: FLambda<P>,
    b_tilda: FLambda<P>,
) -> Chall3<P> {
    h2_chall3::<P>(chall2, &a_tilda, &b_tilda)
}

fn bits_to_u8_many(bits: &[F2]) -> Vec<u8> {
    let mut idx = 0;
    let mut b = 0u8;
    let mut out = vec![];

    for bit in bits.iter() {
        b |= (if *bit == F2::ZERO { 0 } else { 1 }) << idx;
        if idx == 7 {
            idx = 0;
            out.push(b);
            b = 0u8; // reset
        } else {
            idx += 1;
        }
    }
    if idx != 0 {
        out.push(b);
    }
    out
}

/// Structure of vole created by the functionality on the prover side.
#[derive(Clone)]
pub struct VoleProver<P: Params> {
    /// Initialization vector.
    iv: IV,
    /// Decommitment for the VOLE commitment.
    decom: Array<Decom<P>, RepetitionParam<P>>,
    /// VOLE corrections.
    corrections: Corrections<P>,
    /// VOLE `u` values.
    pub(crate) u: Vec<F2>,
    /// VOLE `v` values.
    pub(crate) v: Vec<FLambda<P>>,
    /// First challenge.
    pub(crate) chall1: Chall1<P>,
    /// Consistency hash of `u`.
    pub(crate) u_tilda: HashConsistency<P>,
    /// Hash of the consistency hash of `V`.
    pub(crate) h_v: H1<P>,
    /// Length of the extended witness. Corresponds to `ℓ` in the paper.
    extended_witness_len: usize,
}

impl<P: Params> VoleProver<P> {
    /// Create VOLEs given a statement signature.
    ///
    /// Adapted from parts of `FAEST.sign`, Figure 8.2 from the FAEST spec.
    pub(crate) fn create<Secret: AsSecretBytes>(
        statement_sig: &[u8],
        // Corresponds to `sk` in the spec.
        secret: &Secret,
        // Corresponds to `ℓ` in the spec.
        extended_witness_len: usize,
    ) -> Self {
        // Line 2: Hash the statement signature.
        //
        // The output corresponds to `μ` in the spec.
        let hash_of_stmt = H1::hash(statement_sig);

        // Line 3: Compute the seed and IV from the secret and the hash of the
        // statement.
        let (seed, iv) = compute_seed_iv(secret, &hash_of_stmt);

        // Line 5: Commit to the VOLEs.
        let t = Instant::now();
        let VoleCommitment {
            h_com,
            decom,
            corrections,
            u,
            v,
        } = VoleCommitment::create(seed, iv, l_hat::<P>(extended_witness_len));
        log::info!("vole_commit running time: {:?}", t.elapsed());

        // Line 6: Compute first challenge.
        let t = Instant::now();
        let chall1 = compute_chall_1(&hash_of_stmt, &h_com, &corrections, &iv);
        log::info!("compute_chall_1 running time: {:?}", t.elapsed());

        let t = Instant::now();
        let hasher = VoleHasher::<P>::from_seed(chall1.clone(), extended_witness_len);
        log::info!("VoleHasher::from_seed running time: {:?}", t.elapsed());

        // Line 8: Hash `u` --> `u~`.
        let t = Instant::now();
        let u_tilda = hasher.hash(&u);
        log::info!("vole_hash(u) running time: {:?}", t.elapsed());

        // Line 9: Hash `V` column-wise --> `V~`.
        let t = Instant::now();
        let v_tilda = hasher.hash_matrix(&v).iter().flatten().collect::<Vec<_>>();
        assert_eq!(
            v_tilda.len(),
            SecurityParamPadded::<P>::USIZE * SecurityParam::<P>::USIZE
        );
        log::info!("vole_hash(V) running time: {:?}", t.elapsed());

        // Line 10: Hash `V~` in column-major order.
        let h_v = H1::hash(&bits_to_u8_many(&v_tilda));

        // Line 15: Truncate `u`.
        let mut u_mut = u;
        u_mut.truncate(extended_witness_len + SecurityParam::<P>::USIZE);

        // Line 16 and FAEST.AES.AESProve Line 2.
        let t = std::time::Instant::now();
        // NOTE: using `into_par_iter` from rayon here brings a 10x perf improvement on this part.
        let v_lifted = v
            .into_par_iter()
            .take(extended_witness_len + SecurityParam::<P>::USIZE)
            .map(|vi| lift::<P>(&vi))
            .collect();
        log::info!("v_lifted running time: {:?}", t.elapsed());

        Self {
            iv,
            decom,
            corrections,
            u: u_mut,
            v: v_lifted,
            chall1,
            u_tilda,
            h_v,
            extended_witness_len,
        }
    }

    /// Implements get for the functionality on the prover side
    pub(crate) fn decommit(self, chall3: &Chall3<P>) -> PartialDecommitment<P> {
        let t = std::time::Instant::now();
        let pdecom = vole_open(chall3, &self.decom);
        log::info!("vole_open running time: {:?}", t.elapsed());

        PartialDecommitment {
            pdecom,
            corrections: self.corrections,
            iv: self.iv,
            u_tilda: self.u_tilda,
            extended_witness_len: self.extended_witness_len,
        }
    }
}

/// Partial decommitment produced by the prover.
pub struct PartialDecommitment<P: Params> {
    pdecom: Array<Pdecom<P>, RepetitionParam<P>>,
    corrections: Corrections<P>,
    iv: IV,
    /// VOLE hash of `u`.
    u_tilda: HashConsistency<P>,
    /// Length of the extended witness. `ℓ` in the paper.
    extended_witness_len: usize,
}

impl<P: Params> DecommitmentSerde for PartialDecommitment<P> {
    fn proof_size_estimate(&self) -> usize {
        let size_com = (SecurityParam::<P>::USIZE * 2) / 8;
        let size_key = SecurityParam::<P>::USIZE / 8;
        let pdecom_bytes =
            RepetitionParam::<P>::USIZE * (self.pdecom[2].0.len() * size_key + size_com);

        let corrections_bytes = (self.corrections.length() / 8) * (RepetitionParam::<P>::USIZE - 1);

        let iv_bytes = 16;
        // FIXME(hamlinb): Should this be (SECURITY_PARAM + B) / 8?
        let u_tilda_bytes = SecurityParamPadded::<P>::USIZE / 8;

        pdecom_bytes + corrections_bytes + iv_bytes + u_tilda_bytes
    }
}

/// Structure of VOLE created by the functionality on the verifier side.
#[derive(Clone)]
pub struct VoleVerifier<P: Params> {
    /// correlations on verifier side. This should have length `l + SecurityParam`.
    pub(crate) q: Vec<Array<F8b, RepetitionParam<P>>>,
    /// Consistency check.
    u_tilda: HashConsistency<P>,
    /// Consistency check. TODO: update challenge appropriately!!
    h_v: H1<P>,
    /// secret key
    pub(crate) delta: Array<F8b, RepetitionParam<P>>,
    /// Size of extended witness. `ell` in the paper.
    pub(crate) l: usize,
}

impl<P: Params> VoleVerifier<P> {
    /// Create VOLEs given a statement signature and a proof, on the verifier side.
    ///
    /// Adapted from parts of FAEST.verify from Fig. 8.2
    #[inline(never)]
    pub(crate) fn create(
        statement_sig: &[u8],
        decommitment_prover: &PartialDecommitment<P>,
        chall3: &Chall3<P>,
    ) -> Self {
        // line 1
        let PartialDecommitment {
            corrections,
            u_tilda,
            pdecom,
            iv,
            extended_witness_len,
        } = decommitment_prover;

        // line 2
        let mu: H1<P> = H1::hash(statement_sig);

        // lines 3-4
        let t = std::time::Instant::now();
        let (h, q) = vole_reconstruct::<P>(chall3, pdecom, *iv, l_hat::<P>(*extended_witness_len));
        log::info!("vole_reconstruct running time: {:?}", t.elapsed());

        // line 5
        let chall1 = compute_chall_1(&mu, &h, corrections, iv);

        // lines 6-14
        let t = std::time::Instant::now();
        let q_f8arrs =
            apply_corrections_to_q(q, chall3, corrections, l_hat::<P>(*extended_witness_len));
        log::info!("apply_corrections_to_q running time: {:?}", t.elapsed());

        // line 15
        // hash column-wise Q\tilda + D\tilda
        let t = std::time::Instant::now();
        let hasher = VoleHasher::<P>::from_seed(chall1, *extended_witness_len);
        let q_tilda = hasher
            .hash_matrix(&q_f8arrs)
            .iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            q_tilda.len(),
            SecurityParamPadded::<P>::USIZE * SecurityParam::<P>::USIZE
        );

        log::info!("vole_hash(Q) running time: {:?}", t.elapsed());

        // line 11
        let t = std::time::Instant::now();
        let big_d = recompose_d(chall3, u_tilda);
        log::info!("recompose_d running time: {:?}", t.elapsed());

        // line 16
        let t = std::time::Instant::now();
        let q_xor_d: Vec<F2> = q_tilda
            .iter()
            .zip(big_d.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        log::info!("Q + D running time: {:?}", t.elapsed());

        let h_v = H1::hash(&bits_to_u8_many(&q_xor_d));

        // compute the secret key (AESVerify, line 1)
        let delta = compute_secret_key::<P>(chall3);

        // Truncate the qs (part of line 19)
        let mut q = q_f8arrs;
        q.truncate(extended_witness_len + SecurityParam::<P>::USIZE);

        Self {
            q,
            u_tilda: u_tilda.clone(),
            h_v,
            delta,
            l: *extended_witness_len,
        }
    }

    pub(crate) fn u_tilda(&self) -> &HashConsistency<P> {
        &self.u_tilda
    }
    pub(crate) fn h_v(&self) -> &H1<P> {
        &self.h_v
    }
}

/// Adpation of FAEST Verify function Fig. 8.3
#[cfg(test)]
pub(crate) fn verify<P: Params>(
    chall3: &Chall3<P>,
    chall2: Chall2<P>,
    a_tilda: FLambda<P>,
    b_tilda: FLambda<P>,
) -> bool {
    // Line 20
    let chall3_prime = compute_chall_3::<P>(&chall2, a_tilda, b_tilda);

    chall3_prime == *chall3
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;
    use std::sync::Once;

    use super::{Chall1, Chall2, H1, HashConsistency};
    use super::{VoleProver, VoleVerifier, verify};
    use crate::parameters::{FLambda, P, SecurityParam, SecurityParamBytes, Xof};
    use crate::vole::consistency_check::flambda_from_bytes_array;
    use crate::vole::functionality::compute_chall_3;
    use crate::vole::lift;
    use hybrid_array::{Array, typenum::Unsigned};
    use rand::rng;
    use rayon::prelude::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F2, F8b};
    use swanky_serialization::CanonicalSerialize;

    static INIT: Once = Once::new();

    fn init_logger() {
        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .try_init();
        });
    }

    /// Compute second challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
    pub(crate) fn compute_chall_2(
        chall1: &Chall1<P>,
        u_tilda: HashConsistency<P>,
        h_v: H1<P>,
        masked_witnesses: &[F2],
    ) -> Chall2<P> {
        let mut out = Chall2::<P>::default();

        let mut hasher = Xof::<P>::default();
        hasher.update(chall1);
        hasher.update(u_tilda.pack_to_bytes().as_slice());
        hasher.update(h_v.as_ref());

        // pack the binary field values into bytes
        for chunk in masked_witnesses.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b == F2::ONE {
                    byte |= 1 << i;
                }
            }
            // TODO: for performance, accumulate the bytes in say 64 and hash that.
            hasher.update(&[byte]);
        }

        hasher.update(&[2u8]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out);
        out
    }

    fn test_vole_prover_and_verifier(how_many: usize) {
        let rng = &mut rng();

        let statement_sig = vec![1u8];
        let secret = repeat_with(|| F2::random(rng))
            .take(1000)
            .collect::<Vec<F2>>();

        let t_create_vole_prover = std::time::Instant::now();
        let vole_prover = VoleProver::create(&statement_sig, &secret, how_many);
        log::info!(
            "1: t_create_vole_prover: {:?}",
            t_create_vole_prover.elapsed()
        );

        // Let's clone u and v so that we can test the VOLE fundamental equality at the end.
        let t_copy_challenges = std::time::Instant::now();
        let u = vole_prover.u.clone();
        let v = vole_prover.v.clone();

        let dummy_masked = vec![];
        let chall2 = compute_chall_2(
            &vole_prover.chall1,
            vole_prover.u_tilda.clone(),
            vole_prover.h_v.clone(),
            &dummy_masked,
        );
        let dummy_a_tilda = FLambda::<P>::ZERO;
        let dummy_b_tilda = FLambda::<P>::ZERO;
        let chall3 = compute_chall_3::<P>(&chall2, dummy_a_tilda, dummy_b_tilda);
        log::info!("2: t_copy_challenges: {:?}", t_copy_challenges.elapsed());

        let t_decommit_prover = std::time::Instant::now();
        let decommitment_prover = vole_prover.decommit(&chall3);
        log::info!("3: t_decommit_prover: {:?}", t_decommit_prover.elapsed());

        let t_vole_verifier = std::time::Instant::now();
        let vole_v = VoleVerifier::create(&statement_sig, &decommitment_prover, &chall3);
        log::info!("4: t_vole_verifier: {:?}", t_vole_verifier.elapsed());

        assert_eq!(vole_v.q.len(), vole_v.l + SecurityParam::<P>::USIZE);

        let t_verify = std::time::Instant::now();
        let b = verify::<P>(&chall3, chall2, dummy_a_tilda, dummy_b_tilda);
        log::info!("5: t_verify: {:?}", t_verify.elapsed());

        let t_finalcheck = std::time::Instant::now();
        let delta_lifted: FLambda<P> = lift::<P>(&vole_v.delta);
        let q_lifted: Vec<FLambda<P>> = vole_v.q.into_par_iter().map(|qi| lift::<P>(&qi)).collect();
        for pos in 0..how_many {
            assert_eq!(v[pos] + u[pos] * delta_lifted, q_lifted[pos]);
        }
        log::info!("6: t_finalcheck: {:?}", t_finalcheck.elapsed());

        assert!(b);
    }

    #[test]
    fn test_vole_prover_verifier() {
        let perf = false; // toggle to true for using this test for performance testing the generation of VOLEs
        if !perf {
            test_vole_prover_and_verifier(100);
        } else {
            // Same test but more voles drawn and printing the logs to monitor the timing of the different components

            // if log-level `RUST_LOG` not already set, then set to info
            init_logger();

            let t = std::time::Instant::now();
            test_vole_prover_and_verifier(10_000_000);
            log::info!("VOLE-it-Head completed in: {:?}", t.elapsed());
        }
    }

    #[test]
    fn test_form() {
        let v: Array<_, SecurityParamBytes<P>> = Array::from_fn(|_| 27u8);
        let t: FLambda<P> = flambda_from_bytes_array::<P>(v.as_slice()).unwrap();
        assert_eq!(t.to_bytes()[0], 27u8);
        assert_eq!(t.to_bytes()[1], 27u8);

        let v = 43u8;
        let v_f8b: F8b = F8b::from_bytes(&[v].into()).unwrap();
        let v_back: u8 = v_f8b.to_bytes()[0];
        assert_eq!(v_back, 43u8);
    }
}
