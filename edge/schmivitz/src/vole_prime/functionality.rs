// line Contains the main functionalities VOLE.P1/2/3 and VOLE.V

#![allow(clippy::needless_range_loop)]

use swanky_field::PrimeFiniteField;

use super::all_but_one_vc::{chall_fp_vec_to_bytes_vec, h1_on_coms};
use crate::parameters::MAX_LIMBS_SUPPORTED;
use crate::vole::crypto_primitives::{Com, IV, Prg};
use crate::vole_prime;
use crate::vole_prime::all_but_one_vc::{get_chall_for_ith_tree, Decom};
use crate::vole_prime::crypto_primitives::{pPRG, prg_compact_to_fp};
use crate::vole_prime::reed_solomon::reed_solomon_encode;
use crate::vole_prime::utils::fp_a_gt_fp_b;
use crate::vole_prime::{
    all_but_one_vc::{open, Pdecom},
    commit_reconstruct::{vole_commit, vole_verify, Commit},
    consistency_check::{compute_Delta_Chall, compute_Hv_Chall, vole_hash},
    convert_to_vole::Corrections,
    crypto_primitives::{h1, H1},
};

#[derive(Clone)]
#[allow(unused)]
pub(crate) struct VoleProver<Fp: PrimeFiniteField> {
    pub(crate) com: Com,
    pub(crate) C: Corrections<Fp>,
    pub(crate) chall: Vec<Fp>,
    pub(crate) U_tilde: Vec<Fp>,
    pub(crate) h_small: H1,
    pub(crate) delta: Vec<Fp>,
    pub(crate) decom_delta: Vec<Pdecom>,
}

pub(crate) struct P1<Fp: PrimeFiniteField> {
    pub(crate) V: Vec<Vec<Fp>>,
    pub(crate) decom: Vec<Decom>,
    pub(crate) com: Com,
    pub(crate) U1: Vec<Fp>,
    pub(crate) P: Vec<Fp>,
    pub(crate) C: Vec<Fp>,
}

pub(crate) struct P2<Fp: PrimeFiniteField> {
    pub(crate) h_small: H1,
    pub(crate) U_tilde: Vec<Fp>,
}

#[inline]
pub(crate) fn prover_p1<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: IV,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    d0: usize,
    d1: usize,
) -> P1<Fp> {
    // line VOLE.P1::1-8
    let Commit {
        com,
        decom,
        U1,
        P ,
        V,
        C
    }: vole_prime::commit_reconstruct::Commit<Fp>
    // line VOLE.P1 and BAVC.Commit
    = vole_commit(r, iv, ell_hat, tau, nc, kc, d0, d1);

    P1 {
        V: V,
        decom: decom,
        com: com,
        U1: U1,
        P: P,
        C: C,
    }
}

pub(crate) fn prover_p2<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    U1: Vec<Fp>,
    P: Vec<Fp>,
    chall: Vec<Fp>,
    V: Vec<Vec<Fp>>,
    ell_hat: usize,
    kc: usize,
    nc: usize,
) -> P2<Fp> {
    // line VOLE.P2::2-3
    let mut U1_in_dim: Vec<Vec<Fp>> = Vec::with_capacity(kc);
    let mut P_in_dim: Vec<Vec<Fp>> = Vec::with_capacity(kc);
    for i in 0..kc {
        U1_in_dim.push(Vec::with_capacity(ell_hat));
        P_in_dim.push(Vec::with_capacity(ell_hat));
        // U1_in_dim[i] = Vec::with_capacity(ell_hat);
        for j in 0..ell_hat {
            U1_in_dim[i].push(U1[i * ell_hat + j]);
            P_in_dim[i].push(P[i * ell_hat + j]);
        }
    }

    let U_tilde: Vec<Fp> = vole_hash(chall.clone(), U1_in_dim.clone(), ell_hat, kc);
    assert_eq!(U_tilde.len(), 2 * kc);

    let V_tilde: Vec<Fp> = vole_hash(chall.clone(), V.clone(), ell_hat, nc);

    // line VOLE.P2::4
    let mut inp: Vec<u8> = vec![];
    for i in 0..kc {
        let tmp = V_tilde[i].to_bytes().to_vec();
        inp.extend(tmp);
    }
    for i in kc..nc {
        let tmp = V_tilde[i + kc].to_bytes().to_vec();
        inp.extend(tmp);
    }
    for i in nc..nc + kc {
        let tmp = V_tilde[i - kc].to_bytes().to_vec();
        inp.extend(tmp);
    }
    for i in nc + kc..2 * nc {
        let tmp = V_tilde[i].to_bytes().to_vec();
        inp.extend(tmp);
    }

    log::info!("prover inp 1 {:?}", inp);

    let h_small: H1 = h1(&inp); // This is just a normal hash

    P2 {
        h_small: h_small,
        U_tilde: U_tilde,
    }
}

pub(crate) fn prover_p3<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    delta: Vec<Fp>,
    nc: usize,
    t0: usize,
    d0: usize,
    decom: Vec<Decom>,
) -> Vec<Pdecom> {
    // TODO: Just for debuggung, remove later, for now useful, keep it
    // for i in 0..kc {
    //     for j in 0..ell_hat {
    //         log::info!(
    //             "U: {:?}",
    //             V[i][j].clone() + U1_in_dim[i][j].clone() * delta[i].clone()
    //         );
    //         log::info!(
    //             "P: {:?}",
    //             V[kc + i][j].clone() + P_in_dim[i][j].clone() * delta[kc + i].clone()
    //         );
    //     }
    // }

    // line VOLE.P3::2
    let mut decom_delta: Vec<Pdecom> = Vec::with_capacity(nc);
    let delta_as_bytes = chall_fp_vec_to_bytes_vec(&delta.clone());

    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
    for i in 0..nc {
        let ith_tree_delta_as_bytes =
            get_chall_for_ith_tree(delta_as_bytes.clone(), i, t0, Fp_bit_len);
        decom_delta.push(open(&decom[i], ith_tree_delta_as_bytes, d0));
    }

    decom_delta
}

// line This contains VOLE.P1,P2,P3
#[inline(never)]
pub(crate) fn create_vole_prover<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: IV,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    t0: usize,
    d0: usize,
    d1: usize,
) -> VoleProver<Fp> {
    let P1 {
        V,
        decom,
        U1,
        P,
        com,
        C,
    } = prover_p1(r, iv, ell_hat, tau, nc, kc, d0, d1);

    // INTERACION
    // line verifier "response" after VOLE.P1::9
    let chall: Vec<Fp> = compute_Hv_Chall(com, C.clone(), ell_hat);

    let P2 { h_small, U_tilde } = prover_p2(U1, P, chall.clone(), V, ell_hat, kc, nc);

    // INTERACION
    // line verifier "response" after VOLE.P2::5
    let delta: Vec<Fp> = compute_Delta_Chall(U_tilde.clone(), h_small, nc, d0);

    let decom_delta = prover_p3(delta.clone(), nc, t0, d0, decom);

    // INTERACION
    // line sending non-interactive proof to the Verifier
    VoleProver {
        com,
        C,
        chall,
        U_tilde,
        h_small,
        delta,
        decom_delta,
    }
}

#[derive(Clone)]
pub(crate) struct VoleVerifier<Fp: PrimeFiniteField> {
    pub(crate) is_verifier: bool,
    pub(crate) Q: Vec<Vec<Fp>>,
}

// line This contains VOLE.V
#[inline(never)]
pub(crate) fn verifier<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    proof: VoleProver<Fp>,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    n0: usize,
    d0: usize,
    d1: usize,
    t0: usize,
    nc: usize,
    kc: usize,
) -> VoleVerifier<Fp> {
    // line Serializing stuff from the communication
    let VoleProver {
        com,
        C,
        chall,
        U_tilde,
        h_small,
        delta,
        decom_delta,
    } = proof;

    assert_eq!(delta.len(), nc);

    let mut all_tree_seeds = Vec::with_capacity(tau);
    let mut all_tree_hi = Vec::with_capacity(tau);
    let mut is_verifier: bool = true;

    for tree_idx in 0..tau {
        // line VOLE.V::2
        let seeds;
        let hi;
        if tree_idx < t0 {
            (hi, seeds) = vole_verify(
                decom_delta[tree_idx].clone(),
                delta.clone(),
                iv,
                d0,
                tree_idx,
            );
        } else {
            (hi, seeds) = vole_verify(
                decom_delta[tree_idx].clone(),
                delta.clone(),
                iv,
                d1,
                tree_idx,
            );
        }

        all_tree_seeds.push(seeds);
        all_tree_hi.push(hi);
    }

    let reconstructed_hash = h1_on_coms(&all_tree_hi);

    // line BAVC.Verify::16
    assert_eq!(com, reconstructed_hash);

    // line VOLE.V::3
    if com != reconstructed_hash {
        let err = vec![];
        return VoleVerifier {
            is_verifier: false,
            Q: err,
        };
    }

    let mut q: Vec<Vec<Fp>> = Vec::with_capacity(nc);

    let mut C_in_dim: Vec<Vec<Fp>> = Vec::with_capacity(nc - kc);
    for i in 0..(nc - kc) {
        C_in_dim.push(Vec::with_capacity(ell_hat));
        for j in 0..ell_hat {
            C_in_dim[i].push(C[i * ell_hat + j]);
        }
    }
    for tree_idx in 0..nc {
        let mut q_prime: Vec<Fp> = vec![Fp::ZERO; ell_hat];
        let bit_len = ell_hat * Fp::ZERO.bit_decomposition().len();

        let mut jp = Fp::ZERO;
        for j in 0..n0 {
            // line VOLE.V::5
            let prg: pPRG = pPRG::new(all_tree_seeds[tree_idx][j], iv);
            let tmp = prg_compact_to_fp(prg.prg_compact(bit_len), bit_len);
            // if j == 0 {
            //     log::info!("TMP: {:?}, {:?}", tmp, all_tree_seeds[tree_idx][j]);
            // }
            assert_eq!(tmp.len(), ell_hat);

            // TODO: Get rid of this branching madness, don't wanna feed side-channel papers
            // let delta_uint: crypto_bigint::Uint<MAX_LIMBS_SUPPORTED> = delta[tree_idx].as_int();
            // let jp_uint: crypto_bigint::Uint<MAX_LIMBS_SUPPORTED> =
            //     Fp::try_from(j as u128).unwrap_or_default().as_int();
            // let n0_uint: crypto_bigint::Uint<MAX_LIMBS_SUPPORTED> =
            //     Fp::try_from(n0 as u128).unwrap_or_default().as_int();
            // if delta_uint != jp_uint {
            //     for ell_hat_idx in 0..ell_hat {
            //         let sum_uint = delta_uint.sub_mod(&jp_uint, &n0_uint);
            //         q_prime[ell_hat_idx] += Fp::try_from_int(sum_uint)
            //             .expect("failed from U512 to Fp")
            //             * tmp[ell_hat_idx];
            //     }
            // }

            if delta[tree_idx] != jp {
                for ell_hat_idx in 0..ell_hat {
                    if fp_a_gt_fp_b(delta[tree_idx], jp) == true {
                        q_prime[ell_hat_idx] += (delta[tree_idx] - jp) * tmp[ell_hat_idx];
                    } else if fp_a_gt_fp_b(delta[tree_idx], jp) == false {
                        q_prime[ell_hat_idx] +=
                            (delta[tree_idx] * tmp[ell_hat_idx]) - (jp * tmp[ell_hat_idx]);
                    }
                }
            }
            jp += Fp::ONE;
        }

        // line VOLE.V::6-9
        if tree_idx < kc {
            q.push(q_prime.clone());
            // for ell_hat_idx in 0..ell_hat {
            //     log::info!("Uq {:?}", q_prime[ell_hat_idx]);
            // }
        } else {
            let mut tmp: Vec<Fp> = Vec::with_capacity(ell_hat);
            for ell_hat_idx in 0..ell_hat {
                tmp.push(
                    q_prime[ell_hat_idx] + (delta[tree_idx] * C_in_dim[tree_idx - kc][ell_hat_idx]),
                );
                // log::info!(
                //     "Pq {:?}",
                //     q_prime[ell_hat_idx] + (delta[tree_idx] * C_in_dim[tree_idx - kc][ell_hat_idx])
                // );
            }
            q.push(tmp);
        }
    }

    // line VOLE.V::11
    let Q_tilde = vole_hash(chall, q.clone(), ell_hat, nc);
    assert_eq!(Q_tilde.len(), 2 * nc);

    // line VOLE.V::12
    // U_tilde is 2 * KC dim
    // reed_solom output is 2 * NC
    // First NC elem are the ui's (mesage part), the next NC elems are the Parity P
    let code = reed_solomon_encode(kc, nc, U_tilde, 2, nc);
    assert_eq!(code.len(), 2 * nc);

    let mut prod: Vec<Fp> = Vec::with_capacity(nc);
    for j in 0..kc {
        prod.push(code[j] * delta[j]); // This is the HU1 part
    }
    for j in kc..nc {
        prod.push(code[j] * delta[j - kc]); // This is the HU1 part
    }

    for j in nc..nc + kc {
        prod.push(code[j] * delta[j - nc + kc]); // This is the parity P part
    }
    for j in nc + kc..2 * nc {
        prod.push(code[j] * delta[(j - (nc + kc)) + kc]); // This is the parity P part
    }

    let mut inp: Vec<u8> = vec![];

    for idx in 0..kc {
        let res = Q_tilde[idx] - prod[idx];
        inp.extend(res.to_bytes().to_vec());
    }
    for idx in kc..nc {
        let res = Q_tilde[idx + kc] - prod[idx];
        inp.extend(res.to_bytes().to_vec());
    }
    for idx in nc..nc + kc {
        let res = Q_tilde[idx - kc] - prod[idx];
        inp.extend(res.to_bytes().to_vec());
    }
    for idx in (nc + kc)..(2 * nc) {
        let res = Q_tilde[idx] - prod[idx];
        inp.extend(res.to_bytes().to_vec());
    }

    log::info!("verifier inp 1 {:?}", inp);

    let H_1: H1 = h1(&inp);

    // line VOLE.V:13

    assert_eq!(h_small, H_1);
    for i in 0..h_small.len() {
        if h_small[i] != H_1[i] {
            is_verifier = false;
            break;
        }
    }

    // line VOLE.V::14
    VoleVerifier { is_verifier: is_verifier, Q: q }
}

// line This contains VOLE.V
#[inline(never)]
pub(crate) fn create_vole_verifier<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    proof: VoleProver<Fp>,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    n0: usize,
    d0: usize,
    d1: usize,
    t0: usize,
    nc: usize,
    kc: usize,
) -> VoleVerifier<Fp> {
    verifier(proof, iv, ell_hat, tau, n0, d0, d1, t0, nc, kc)
}

#[cfg(test)]
mod test {

    use std::sync::Once;
use std::time::Instant;

    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    use crate::vole_prime::{
        self,
        commit_reconstruct::get_prime_ell_hat_len,
    };

    use crate::parameters::{D0, D1, KC, N0, NC, T0, TAU};

    use crate::vole::crypto_primitives::IV;

    use super::{create_vole_prover, create_vole_verifier};

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

        let r: IV = [0xee; 16];
        let iv: IV = [0xee; 16];
        let ell_hat = get_prime_ell_hat_len(1);

        let start = Instant::now();
        let vole_prover: vole_prime::functionality::VoleProver<Fp> =
            create_vole_prover(r, iv, ell_hat, TAU, NC, KC, T0, D0, D1);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        log::info!("Prover Time elapsed: {} ms", millis);

        let start = Instant::now();
        let vole_verifier =
            create_vole_verifier(vole_prover, iv, ell_hat, TAU, N0, D0, D1, T0, NC, KC);
        let duration = start.elapsed();
        let millis = duration.as_millis();
        log::info!("Verifier Time elapsed: {} ms", millis);

        assert!(vole_verifier.is_verifier);
    }

    // NOTE: RUSTFLAGS="-C debuginfo=2" cargo test --release test_vole_prover_and_verifier_f256p -- --nocapture

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
