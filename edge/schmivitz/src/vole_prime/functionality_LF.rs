#![allow(clippy::needless_range_loop)]

use std::num::FpCategory;

use swanky_field::PrimeFiniteField;

use crate::{
    vole::crypto_primitives::{Com, H1, IV}, vole_prime::{
        consistency_check::{compute_Delta_Chall, compute_Hv_Chall}, convert_to_vole::Corrections, crypto_primitives::h1, functionality::{
            P1, P2, VoleProver, VoleVerifier, prover_p1, prover_p2, prover_p3, verifier,
        }, reed_solomon::reed_solomon_encode,
    },
};
use crate::vole::all_but_one_vc::Keys;
use crate::vole::all_but_one_vc::Decom;
use crate::vole::all_but_one_vc::Pdecom;

pub(crate) struct P1_LF<Fp: PrimeFiniteField> {
    pub(crate) p1: P1<Fp>,
    pub(crate) p2: P2<Fp>,
    pub(crate) chall: Vec<Fp>,
}

pub(crate) struct P2_LF<Fp: PrimeFiniteField> {
    pub(crate) delta: Vec<Fp>,
    pub(crate) decom_delta: Vec<Pdecom>,
    pub(crate) h_large: H1,
    pub(crate) S: Vec<Fp>,
}

pub(crate) struct VoleProver_LF<Fp: PrimeFiniteField> {
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
}

#[derive(Clone)]
pub(crate) struct VoleVerifier_LF<Fp: PrimeFiniteField> {
    pub(crate) is_verifier: bool,
    pub(crate) S_LF: Vec<Fp>,
}

#[inline]
pub(crate) fn prover_LF_p1<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: IV,
    iv: IV,
    two_ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    d0: usize,
    d1: usize,
) -> P1_LF<Fp> {
    let p1 = prover_p1(r, iv, two_ell_hat, tau, nc, kc, d0, d1);
    let P1 {
        ref V,
        decom: _,
        ref U1,
        ref P,
        ref com,
        ref C,
    } = p1;

    assert_eq!(V[0].len(), two_ell_hat);
    assert_eq!(V.len(), nc);

    // "INTERACION"
    let chall: Vec<Fp> = compute_Hv_Chall(com.clone(), C.to_vec(), two_ell_hat);

    let p2 = prover_p2(
        U1.clone(),
        P.clone(),
        chall.clone(),
        V.clone(),
        two_ell_hat,
        kc,
        nc,
    );

    P1_LF {
        p1: p1,
        p2: p2,
        chall: chall,
    }
}

#[inline]
pub(crate) fn prover_LF_p2<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    U1: Vec<Fp>,
    P: Vec<Fp>,
    V: Vec<Vec<Fp>>,
    delta_prime: Vec<Fp>,
    ell_hat: usize,
    nc: usize,
    kc: usize,
    t0: usize,
    d0: usize,
    decom: Vec<Decom>,
) -> P2_LF<Fp> {
    assert_eq!(2 * kc, nc);
    assert_eq!(P.len(), 2 * ell_hat * (nc - kc));
    assert_eq!(U1.len(), 2 * ell_hat * kc);
    assert_eq!(V[0].len(), 2 * ell_hat);
    assert_eq!(V.len(), nc);

    // In V, first index is Nc, then is ell_hat
    let mut V_top: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    let mut V_bot: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    for _ in 0..ell_hat {
        V_top.push(Vec::with_capacity(nc));
        V_bot.push(Vec::with_capacity(nc));
    }
    // Copying stuff from V to V_top and V_bot
    for i in 0..ell_hat {
        for j in 0..nc {
            V_top[i].push(V[j][i]);
        }
    }
    for i in ell_hat..2 * ell_hat {
        for j in 0..nc {
            V_bot[i - ell_hat].push(V[j][i]);
        }
    }

    // Getting the U1 and P and transforming the major
    // U dim -> 2*ell_hat * nc, first nc half is U1, second half is P
    let mut U: Vec<Vec<Fp>> = Vec::with_capacity(2 * ell_hat);
    for _ in 0..ell_hat * 2 {
        U.push(Vec::with_capacity(nc));
    }
    for i in 0..2 * ell_hat {
        for j in 0..kc {
            U[i].push(U1[j * 2 * ell_hat + i]); // switching majors
        }
    }
    for i in 0..2 * ell_hat {
        for j in 0..kc {
            U[i].push(P[j * 2 * ell_hat + i]); // switching majors
        }
    }
    let mut U_top: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    let mut U_bot: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    for _ in 0..ell_hat {
        U_top.push(Vec::with_capacity(nc));
        U_bot.push(Vec::with_capacity(nc));
    }
    // Copying stuff from V to V_top and V_bot
    for i in 0..ell_hat {
        for j in 0..kc {
            U_top[i].push(U[i][j]);
        }
    }
    for i in ell_hat..2 * ell_hat {
        for j in 0..kc {
            U_bot[i - ell_hat].push(U[i][j]);
        }
    }

    let mut S: Vec<Fp> = Vec::with_capacity(ell_hat * kc);
    for i in 0..ell_hat {
        for j in 0..kc {
            S.push(U_bot[i][j] + (U_top[i][j] * delta_prime[0]));
        }
    }

    let mut V_tmp = Vec::with_capacity(ell_hat * kc * 2);
    for i in 0..ell_hat {
        for j in 0..nc {
            V_tmp.push(V_bot[i][j] + (V_top[i][j] * delta_prime[0]));
        }
    }

    let mut inp: Vec<u8> = vec![];
    for idx in 0..ell_hat {
        for i in 0..kc {
            let tmp = V_tmp[idx * nc + i].to_bytes().to_vec();
            inp.extend(tmp);
        }
    }
    for idx in 0..ell_hat {
        for i in kc..nc {
            let tmp = V_tmp[idx * nc + i].to_bytes().to_vec();
            inp.extend(tmp);
        }
    }

    let h_large: H1 = h1(&inp);

    log::info!("prover inp 2 {:?}", inp);

    let delta: Vec<Fp> = compute_Delta_Chall(S.clone(), h_large, nc, d0);

    let decom_delta = prover_p3(delta.clone(), nc, t0, d0, decom);

    P2_LF {
        delta,
        decom_delta,
        h_large,
        S,
    }
}

#[inline(never)]
pub(crate) fn verifier_LF<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    proof: VoleProver_LF<Fp>,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    n0: usize,
    d0: usize,
    d1: usize,
    t0: usize,
    nc: usize,
    kc: usize,
) -> VoleVerifier_LF<Fp> {
    let VoleProver_LF {
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
    } = proof;

    assert_eq!(delta_prime.len(), 1);
    assert_eq!(delta.len(), nc);
    assert_eq!(S.len(), ell_hat * kc);

    let voleprover = VoleProver {
        com: *com,
        C: C.to_vec(),
        chall: chall.to_vec(),
        U_tilde: U_tilde.to_vec(),
        h_small: *h_small,
        delta: delta.to_vec(),
        decom_delta: decom_delta.to_vec(),
    };

    let ret = verifier(voleprover, iv, 2 * ell_hat, tau, n0, d0, d1, t0, nc, kc);

    let VoleVerifier { ref is_verifier, ref Q } = ret;

    assert_eq!(Q.len(), nc);
    assert_eq!(Q[0].len(), 2 * ell_hat);
    assert_eq!(S.len(), ell_hat * kc);

    let mut Q_top: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    let mut Q_bot: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    for _ in 0..ell_hat {
        Q_top.push(Vec::with_capacity(nc));
        Q_bot.push(Vec::with_capacity(nc));
    }
    for i in 0..ell_hat {
        for j in 0..nc {
            Q_top[i].push(Q[j][i]);
        }
    }
    for i in ell_hat..2 * ell_hat {
        for j in 0..nc {
            Q_bot[i - ell_hat].push(Q[j][i]);
        }
    }

    let mut Q_dash: Vec<Fp> = Vec::with_capacity(ell_hat * nc);
    for i in 0..ell_hat {
        for j in 0..nc {
            Q_dash.push(Q_bot[i][j] + (Q_top[i][j] * delta_prime[0]));
        }
    }

    // The first ell_hat * kc is the msg and the second ell_hat * kc is the parity
    let code = reed_solomon_encode(kc, nc, S.clone(), ell_hat, nc);
    assert_eq!(code.len(), ell_hat * kc * 2);

    let mut prod: Vec<Fp> = Vec::with_capacity(ell_hat * nc);
    for i in 0..ell_hat {
        for j in 0..kc {
            prod.push(code[i * kc + j] * delta[j]); // This is the HU1 part
        }
    }
    for i in 0..ell_hat {
        for j in 0..kc {
            prod.push(code[(ell_hat * kc) + (i * kc) + j] * delta[j + kc]); // This is the parity P part
        }
    }

    let mut inp: Vec<u8> = vec![];
    for i in 0..ell_hat {
        for idx in 0..kc {
            let res = Q_dash[i * nc + idx] - prod[i * kc + idx];
            inp.extend(res.to_bytes().to_vec());
        }
    }
    for i in 0..ell_hat {
        for idx in kc..nc {
            let res = Q_dash[i * nc + idx] - prod[(ell_hat * kc) + (i * kc) + (idx - kc)];
            inp.extend(res.to_bytes().to_vec());
        }
    }

    log::info!("verifier inp 2 {:?}", inp);

    let h1: H1 = h1(&inp);

    assert_eq!(*h1.as_ref(), *h_large.as_ref());

    VoleVerifier_LF {
        is_verifier: true,
        S_LF: S.to_vec(),
    }
}

#[inline(never)]
pub(crate) fn create_vole_LF_prover<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: IV,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    t0: usize,
    d0: usize,
    d1: usize,
) -> VoleProver_LF<Fp> {
    let p1_LF = prover_LF_p1(r, iv, 2 * ell_hat, tau, nc, kc, d0, d1);
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

    // INTERACION
    let delta_prime: Vec<Fp> = compute_Delta_Chall(U_tilde.clone(), h_small, 1, d0);
    // let mut delta_prime = Vec::with_capacity(nc);
    // for _ in 0..nc {
    //     delta_prime.push(delta_prime_tmp[0]);
    // }

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
    VoleProver_LF {
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
    }
}

#[inline(never)]
pub(crate) fn create_vole_LF_verifier<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    proof: VoleProver_LF<Fp>,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    n0: usize,
    d0: usize,
    d1: usize,
    t0: usize,
    nc: usize,
    kc: usize,
) -> VoleVerifier_LF<Fp> {
    verifier_LF(proof, iv, ell_hat, tau, n0, d0, d1, t0, nc, kc)
}

#[cfg(test)]
mod test {

    use std::sync::Once;
    use std::time::Instant;

    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    use crate::vole_prime::functionality_LF::create_vole_LF_verifier;
    use crate::vole_prime::{
        self,
        commit_reconstruct::get_prime_ell_hat_len,
        // parameters::{KC, NC, D0, D1, N0, N1, T0, T1, TAU}
    };

    use crate::parameters::{D0, D1, KC, N0, NC, T0, TAU};

    use crate::vole::crypto_primitives::IV;

    use super::create_vole_LF_prover;

    static INIT: Once = Once::new();
    fn init_logger() {
        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .try_init();
        });
    }

    fn test_vole_prover_and_verifier<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {

        // if log-level `RUST_LOG` not already set, then set to info
        init_logger();

        // TODO: changing to 0xff overflows
        let r: IV = [0x01; 16];
        let iv: IV = [0x01; 16];
        let ell_hat = get_prime_ell_hat_len(1);
        // let ell_hat = 1;

        let start = Instant::now();
        let vole_prover: vole_prime::functionality_LF::VoleProver_LF<Fp> =
            create_vole_LF_prover(r, iv, ell_hat, TAU, NC, KC, T0, D0, D1);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        log::info!("Prover Time elapsed: {} ms", millis);

        let start = Instant::now();
        let vole_verifier =
            create_vole_LF_verifier(vole_prover, iv, ell_hat, TAU, N0, D0, D1, T0, NC, KC);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        log::info!("Verifier Time elapsed: {} ms", millis);

        // assert!(vole_verifier.is_verifier);
    }

    // RUSTFLAGS="-C debuginfo=2" cargo test --release test_vole_prover_and_verifier_f256p -- --nocapture

    #[test]
    fn test_vole_prover_and_verifier_f32p() {
        test_vole_prover_and_verifier::<F32p>();
    }
    #[test]
    fn test_vole_prover_and_verifier_f64p() {
        test_vole_prover_and_verifier::<F64p>();
    }
    #[test]
    fn test_vole_prover_and_verifier_frs127p() {
        test_vole_prover_and_verifier::<Frs127p>();
    }
    #[test]
    fn test_vole_prover_and_verifier_f128p() {
        test_vole_prover_and_verifier::<F128p>();
    }
    #[test]
    fn test_vole_prover_and_verifier_f256p() {
        test_vole_prover_and_verifier::<F256p>();
    }
}
