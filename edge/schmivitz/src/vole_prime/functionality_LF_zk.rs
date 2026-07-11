#![allow(clippy::needless_range_loop)]

use std::num::FpCategory;

use swanky_field::PrimeFiniteField;

use crate::{
    vole::crypto_primitives::{Com, IV},
    vole_prime::{
        all_but_one_vc::{Decom, Pdecom},
        consistency_check::{compute_Delta_Chall, compute_Hv_Chall},
        convert_to_vole::Corrections,
        crypto_primitives::{h1, H1},
        functionality::{
            prover_p1, prover_p2, prover_p3, verifier, VoleProver, VoleVerifier, P1, P2,
        },
        functionality_LF::{
            prover_LF_p1, prover_LF_p2, verifier_LF, VoleProver_LF, VoleVerifier_LF, P1_LF, P2_LF,
        },
        reed_solomon::reed_solomon_encode,
    },
};

pub(crate) struct ZK_PROVER<Fp: PrimeFiniteField> {
    pub(crate) com: Com,
    pub(crate) C: Corrections<Fp>,
    pub(crate) chall: Vec<Fp>,
    pub(crate) U_tilde: Vec<Fp>,
    pub(crate) h_small: H1,
    pub(crate) delta_prime: Vec<Fp>,
    pub(crate) delta: Vec<Fp>,
    pub(crate) decom_delta: Vec<Pdecom>,
    pub(crate) h_large: H1,
    pub(crate) S: Vec<Fp>,
    pub(crate) D: Vec<Fp>,
    pub(crate) chi: Vec<Fp>,
    pub(crate) a_tilde: Vec<Fp>,
}

#[inline(never)]
pub(crate) fn f_cnsrts<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    i: usize,
    h: usize,
    kc: usize,
    ell: usize,
    inp: Vec<Fp>,
) -> Vec<Fp> {
    let mut ret = Vec::with_capacity(kc);
    for _ in 0..kc {
        ret.push(Fp::ZERO);
    }

    ret
}

#[inline(never)]
pub(crate) fn zk_prover<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: IV,
    iv: IV,
    ell: usize,
    ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    t0: usize,
    d0: usize,
    d1: usize,
    deg: usize,
    t: usize,
    W: Vec<Fp>,
) -> ZK_PROVER<Fp> {
    let two_ell_hat = 2 * ell_hat;
    let deg_minus_one = deg - 1;
    let deg_minus_two = deg - 2;
    let p1_LF: P1_LF<Fp> = prover_LF_p1(r, iv, two_ell_hat, tau, nc, kc, d0, d1);
    let P1_LF { p1, p2, chall } = p1_LF;
    let P1 {
        V,
        decom,
        com,
        U1,
        P,
        C,
    } = p1;
    let P2 { h_small, U_tilde } = p2;

    assert_eq!(V.len(), nc);
    assert_eq!(V[0].len(), two_ell_hat);
    assert_eq!(U1.len(), two_ell_hat * kc);
    assert_eq!(P.len(), two_ell_hat * (nc - kc));
    assert_eq!(C.len(), two_ell_hat * (nc - kc));
    assert_eq!(U_tilde.len(), 2 * kc);
    assert_eq!(h_small.len(), 32);
    assert_eq!(W.len(), ell * kc);

    let mut D = Vec::with_capacity(ell * kc);
    for i in 0..kc * ell {
        D.push(W[i] - U1[i]);
    }

    let mut U_tilde_plus_D = U_tilde.clone();
    U_tilde_plus_D.extend(D.clone());

    // ######################### INTERACTION #####################
    // TODO: Writing a generic compute_Delta_Chall function would be nice, for all other cases there were only two vars being passes
    let chi: Vec<Fp> = compute_Delta_Chall(U_tilde_plus_D, h_small, t, d0);
    // ##############################################
    assert_eq!(chi.len(), t);

    let mut U: Vec<Fp> = Vec::with_capacity(two_ell_hat * nc);
    for i in 0..kc {
        for j in 0..two_ell_hat {
            U.push(U1[i * two_ell_hat + j]);
        }
    }
    for i in 0..kc {
        for j in 0..two_ell_hat {
            U.push(P[i * two_ell_hat + j]);
        }
    }
    let r = U[ell_hat * nc..two_ell_hat * nc].to_vec();
    assert_eq!(r.len(), ell_hat * nc);

    let u = U1[ell * kc..(ell + deg_minus_one) * kc].to_vec();
    assert_eq!(u.len(), deg_minus_one * kc);

    let w = W[..ell * kc].to_vec();
    assert_eq!(w.len(), ell * kc);

    let mut A: Vec<Vec<Vec<Fp>>> = Vec::with_capacity(t);
    for i in 0..t {
        A.push(Vec::with_capacity(deg));
        for j in 0..deg {
            A[i].push(Vec::with_capacity(kc));
            for _ in 0..kc {
                A[i][j].push(Fp::ZERO);
            }
        }
    }

    for i in 0..t {
        for h in 0..deg {
            let mut r_plus_W = Vec::with_capacity(ell * kc);

            for k in 0..kc {
                for l in 0..ell {
                    r_plus_W.push(r[k * ell_hat + l] + W[k * ell + l]); // taking the first ell of r from the kc out of nc values
                }
            }

            let tmp = f_cnsrts(i, h, kc, ell, r_plus_W.to_vec());

            for idx in 0..kc {
                A[i][h][idx] += tmp[idx];
            }
        }
    }

    assert_eq!(A.len(), t);
    assert_eq!(A[0].len(), deg);
    assert_eq!(A[0][0].len(), kc);

    let mut a_tilde_0: Vec<Fp> = Vec::with_capacity(kc);
    let mut chiA = vec![Fp::ZERO; kc];
    for i in 0..t {
        for j in 0..kc {
            chiA[j] += chi[i] * A[i][0][j];
        }
    }
    for i in 0..kc {
        a_tilde_0.push(r[i * ell_hat + ell + 1] + chiA[i]);
    }
    assert_eq!(a_tilde_0.len(), kc);

    let mut a_tilde_deg_minus_1: Vec<Fp> = Vec::with_capacity(kc);
    chiA = vec![Fp::ZERO; kc];
    for i in 0..t {
        for j in 0..kc {
            chiA[j] += chi[i] * A[i][deg_minus_one][j];
        }
    }
    for i in 0..kc {
        // TODO: Is this correct??
        a_tilde_deg_minus_1.push(u[i * deg_minus_one] + chiA[i]);
    }
    assert_eq!(a_tilde_deg_minus_1.len(), kc);

    let mut a_tilde_j: Vec<Fp> = Vec::with_capacity(deg_minus_two * kc);
    for j in 0..deg_minus_two {
        let mut chiA = vec![Fp::ZERO; kc];
        for i in 0..t {
            for idx in 0..kc {
                chiA[idx] += chi[i] * A[i][j][idx];
            }
        }
        for i in 0..kc {
            a_tilde_j.push(r[ell_hat * (j + 1)] + u[i * deg_minus_one] + chiA[i]);
        }
    }
    assert_eq!(a_tilde_j.len(), deg_minus_two * kc);

    let mut a_tilde = a_tilde_0.clone();
    for i in 0..(deg_minus_two) {
        a_tilde.extend(a_tilde_j[..(deg_minus_one) * kc].to_vec().clone());
    }
    a_tilde.extend(a_tilde_deg_minus_1.clone());
    assert_eq!(
        a_tilde.len(),
        a_tilde_0.len() + a_tilde_deg_minus_1.len() + a_tilde_j.len()
    );

    let delta_prime: Vec<Fp> = compute_Delta_Chall(a_tilde.clone(), [0; 32], 1, d0);

    let p2_LF = prover_LF_p2(
        U1,
        P,
        V,
        delta_prime.clone(),
        ell_hat,
        nc,
        kc,
        t0,
        d0,
        decom,
    );

    let P2_LF {
        delta,
        decom_delta,
        h_large,
        S,
    } = p2_LF;

    // INTERACION
    ZK_PROVER {
        com,
        C,
        chall,
        U_tilde,
        h_small,
        delta_prime,
        delta,
        decom_delta,
        h_large,
        S,
        D,
        chi,
        a_tilde,
    }
}

#[inline(never)]
pub(crate) fn zk_verifier<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    proof: ZK_PROVER<Fp>,
    iv: IV,
    ell_hat: usize,
    ell: usize,
    tau: usize,
    n0: usize,
    t0: usize,
    d0: usize,
    d1: usize,
    deg: usize,
    t: usize,
    nc: usize,
    kc: usize,
) -> bool {
    let ZK_PROVER {
        ref com,
        ref C,
        ref chall,
        ref U_tilde,
        ref h_small,
        ref delta_prime,
        ref delta,
        ref decom_delta,
        ref h_large,
        ref S,
        ref D,
        ref chi,
        ref a_tilde,
    } = proof;
    let two_ell_hat = 2 * ell_hat;
    let deg_minus_one = deg - 1;

    assert_eq!(com.len(), 32);
    assert_eq!(C.len(), two_ell_hat * (nc - kc));
    assert_eq!(chall.len(), 2 * two_ell_hat); // NOTE: This size comes from VOLE.V::1
    assert_eq!(U_tilde.len(), 2 * kc);
    assert_eq!(h_small.len(), 32);
    assert_eq!(delta_prime.len(), 1);
    assert_eq!(delta.len(), nc);
    assert_eq!(h_large.len(), 32);
    assert_eq!(S.len(), ell_hat * kc);
    assert_eq!(D.len(), ell * kc);
    assert_eq!(chi.len(), t);
    assert_eq!(a_tilde.len(), deg * kc);

    let voleprover = VoleProver {
        com: *com,
        C: C.to_vec(),
        chall: chall.to_vec(),
        U_tilde: U_tilde.to_vec(),
        h_small: *h_small,
        delta: delta.to_vec(),
        decom_delta: decom_delta.to_vec(),
    };

    let proof_LF = VoleProver_LF {
        com: proof.com,
        C: proof.C,
        chall: proof.chall,
        U_tilde: proof.U_tilde,
        h_small: proof.h_small,
        delta_prime: proof.delta_prime.clone(),
        delta: proof.delta,
        decom_delta: proof.decom_delta,
        h_large: proof.h_large,
        S: proof.S.clone(),
    };

    let ret = verifier_LF(proof_LF, iv, ell_hat, tau, n0, d0, d1, t0, nc, kc);

    let VoleVerifier_LF { ref is_verifier, S_LF: _ } = ret;

    if *is_verifier == false {
        return false;
    }

    let mut s_prime: Vec<Fp> = vec![Fp::ZERO; ell_hat * kc];

    for k in 0..kc {
        for l in 0..ell {
            s_prime[k * ell_hat + l] = S[k * ell_hat + l] + (D[k * ell + l] * delta_prime[0]);
        }
    }

    for k in 0..kc {
        for l in 0..deg_minus_one {
            s_prime[k * ell_hat + ell + l] = S[k * ell_hat + ell + l];
        }
    }

    let mut c = vec![Fp::ZERO; t * kc];
    for i in 0..t {
        for h in 0..deg {
            let tmp = f_cnsrts(i, h, kc, ell, s_prime[..ell * kc].to_vec());
            for idx in 0..kc {
                c[i * kc + idx] += tmp[idx];
            }
        }
    }

    let mut s_tilde = vec![Fp::ZERO; kc];
    for i in 0..kc {
        for ti in 0..t {
            s_tilde[i] += chi[ti] * c[i * t + ti];
        }
        s_tilde[i] *= delta_prime[0];

        for j in 1..deg_minus_one {
            s_tilde[i] += s_prime[i * ell_hat + ell + j] * delta_prime[0].pow((j - 1) as u128);
        }
    }
    assert_eq!(s_tilde.len(), kc);

    let mut a_tilde_sum = vec![Fp::ZERO; kc];
    for i in 0..kc {
        for j in 0..deg_minus_one {
            a_tilde_sum[i] += a_tilde[i * deg_minus_one + j] * delta_prime[0].pow(i as u128);
        }
    }

    assert_eq!(s_tilde, a_tilde_sum);

    true
}

#[cfg(test)]
mod test {

    use std::time::Instant;

    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    use crate::proof;
    use crate::vole_prime::functionality_LF::{create_vole_LF_verifier, VoleProver_LF};
    use crate::vole_prime::functionality_LF_zk::{zk_prover, zk_verifier, ZK_PROVER};
    use crate::vole_prime::{
        self,
        commit_reconstruct::get_prime_ell_hat_len,
        // parameters::{KC, NC, D0, D1, N0, N1, T0, T1, TAU}
    };

    use crate::parameters::{D0, D1, KC, MAX_DEG, N0, N1, NC, T0, TAU};

    use crate::vole::crypto_primitives::IV;

    fn test_vole_prover_and_verifier<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        // TODO: changing to 0xff overflows
        let r: IV = [0x01; 16];
        let iv: IV = [0x01; 16];
        let deg = MAX_DEG;
        let ell = 1;
        let ell_hat = ell + deg - 1;
        let tau = TAU;
        let nc = NC;
        let kc = KC;
        let t0 = T0;
        let d0 = D0;
        let d1 = D1;
        let n0 = N0;
        let n1 = N1;

        let t = 1;

        // TODO: Just making up some witness here
        let mut W: Vec<Fp> = Vec::with_capacity(ell * kc);
        for _ in 0..ell * kc {
            W.push(Fp::ZERO);
        }

        let start = Instant::now();
        let proof = zk_prover(r, iv, ell, ell_hat, tau, nc, kc, t0, d0, d1, deg, t, W);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        println!("Prover Time elapsed: {} ms", millis);

        let start = Instant::now();
        let vole_verifier =
            zk_verifier(proof, iv, ell_hat, ell, tau, n0, t0, d0, d1, deg, t, nc, kc);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        println!("Verifier Time elapsed: {} ms", millis);

        assert!(vole_verifier == true);
    }

    // RUSTFLAGS="-C debuginfo=2" cargo test --release test_vole_prover_and_verifier_f256p -- --nocapture

    // #[test]
    // fn test_vole_prover_and_verifier_f32p() {
    //     test_vole_prover_and_verifier::<F32p>();
    // }
    // #[test]
    // fn test_vole_prover_and_verifier_f64p() {
    //     test_vole_prover_and_verifier::<F64p>();
    // }
    // #[test]
    // fn test_vole_prover_and_verifier_frs127p() {
    //     test_vole_prover_and_verifier::<Frs127p>();
    // }
    #[test]
    fn test_vole_prover_and_verifier_f128p() {
        test_vole_prover_and_verifier::<F128p>();
    }
    // #[test]
    // fn test_vole_prover_and_verifier_f256p() {
    //     test_vole_prover_and_verifier::<F256p>();
    // }
}
