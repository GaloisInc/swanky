#![allow(clippy::needless_range_loop)]
use crate::parameters::T0;
use crate::vole::crypto_primitives::{Com, Seed, IV};
use crate::vole_prime::all_but_one_vc::{commit, open, reconstruct, Decom, Pdecom};
use crate::vole_prime::convert_to_vole::convert_to_vole;
use crate::vole_prime::crypto_primitives::{h1, pPRG};
use crate::vole_prime::reed_solomon::reed_solomon_encode;
use rand::Rng;
use proptest::bits::usize;
use std::sync::mpsc::channel;
use std::thread;
use swanky_field::PrimeFiniteField;

use super::all_but_one_vc::{chall_fp_vec_to_bytes_vec, get_chall_for_ith_tree};
use super::crypto_primitives::H1;

#[allow(dead_code)]
pub(crate) struct Commit<Fp: PrimeFiniteField> {
    pub(crate) com: Com,
    pub(crate) decom: Vec<Decom>,
    pub(crate) U1: Vec<Fp>,
    pub(crate) P: Vec<Fp>,
    pub(crate) V: Vec<Vec<Fp>>,
    pub(crate) C: Vec<Fp>,
}

// line VOLE.P1 and BAVC.Commit
#[inline(never)]
pub(crate) fn vole_commit<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    r: Seed,
    iv: IV,
    ell_hat: usize,
    tau: usize,
    nc: usize,
    kc: usize,
    d0: usize,
    d1: usize,
) -> Commit<Fp> {
    let mut decom: Vec<Decom> = Vec::with_capacity(tau);
    let mut com: Vec<Com> = Vec::with_capacity(tau);
    // line BAVC.Commit::1
    let prg_seeds = pPRG::new(r, iv).generate_prg_seeds(tau);

    // line VOLE.P1::4-5
    // u_i should be l + 3 length
    let mut u: Vec<Vec<Fp>> = Vec::with_capacity(nc);
    // v_i should be also (l + 3)*k_b length, where k_b is the depth d of the tree
    let mut v: Vec<Vec<Fp>> = Vec::with_capacity(nc);

    let mut txs = Vec::with_capacity(tau);
    let mut rxs = Vec::with_capacity(tau);

    for _ in 0..tau {
        let (tx, rx) = channel();
        txs.push(tx);
        rxs.push(rx);
    }
    let mut handles = Vec::new();

    // line BAVC.Commit::2
    for i in 0..tau {
        let tx = txs[i].clone();

        let prg_seeds_i = prg_seeds[i];

        if i < T0 {
            let handle = thread::spawn(move || {
                // line BAVC.Commit::3-11
                let (com_i, decom_i, seeds) = commit(prg_seeds_i, iv, d0);
                // line VOLE.P1::4-5
                let (u_i, v_i) = convert_to_vole(seeds, iv, ell_hat, d0);

                tx.send((com_i, decom_i, u_i, v_i)).unwrap();
            });
            handles.push(handle);
        } else {
            let handle = thread::spawn(move || {
                // line BAVC.Commit::3-11
                let (com_i, decom_i, seeds) = commit(prg_seeds_i, iv, d1);

                // if (i > 14) {
                //     println!(
                //         // "VOLE: {:?}, {:?}, {:?}, {:?}, {:?}",
                //         "VOLE: {:?}",
                //         // decom_delta.0,
                //         // ith_tree_delta_bytes,
                //         // iv,
                //         // depth,
                //         seeds
                //     );
                // }

                // line VOLE.P1::4-5
                let (u_i, v_i) = convert_to_vole(seeds, iv, ell_hat, d1);

                tx.send((com_i, decom_i, u_i, v_i)).unwrap();
            });
            handles.push(handle);
        }
    }

    for i in 0..tau {
        let (com_i, decom_i, u_i, v_i) = rxs[i].recv().unwrap();

        com.push(com_i);
        decom.push(decom_i);
        u.push(u_i);
        // line VOLE.P1::6
        v.push(v_i);
    }

    // line VOLE.P1::7
    // let (U1, P) = reed_solomon_encode_prover(ell_hat, kc, nc, u[0..kc].to_vec(), 2 * kc);
    let rs_code = reed_solomon_encode(
        kc,
        nc,
        u[0..kc]
            .iter()
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<Fp>>(),
        ell_hat,
        nc,
    );
    assert_eq!(rs_code.len(), ell_hat * nc);

    // println!("rs_code {:?}", rs_code);

    // line VOLE.P1::8
    let mut U1: Vec<Fp> = Vec::with_capacity(ell_hat * kc);
    for i in 0..kc {
        for j in 0..ell_hat {
            U1.push(rs_code[i * ell_hat + j]);
        }
    }

    let mut P: Vec<Fp> = Vec::with_capacity(ell_hat * (nc - kc));
    for i in kc..nc {
        for j in 0..ell_hat {
            P.push(rs_code[i * ell_hat + j]);
        }
    }
    let mut C: Vec<Fp> = Vec::with_capacity(ell_hat * (nc - kc));
    for i in kc..nc {
        for j in 0..ell_hat {
            C.push(rs_code[i * ell_hat + j] - u[i][j]);
        }
    }

    // line BAVC.Commit::9
    let mut flat_com: Vec<u8> = Vec::with_capacity(nc * 32);

    for i in 0..nc {
        for j in 0..32 {
            flat_com.push(com[i][j]);
        }
    }

    let hcom = h1(&flat_com);

    // line VOLE.P1::9
    Commit {
        com: hcom,
        decom: decom,
        U1: U1,
        P: P,
        V: v,
        C: C,
    }
}

// line VOLE.P3::2
pub(crate) fn vole_open<Fp: PrimeFiniteField>(
    chall: Vec<Fp>,
    decom: Vec<Decom>,
    tau: usize,
    t0: usize,
    d0: usize,
    d1: usize,
) -> Vec<Pdecom> {
    let mut pdecom = Vec::with_capacity(tau);

    let chall_as_bytes = chall_fp_vec_to_bytes_vec(&chall);

    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
    for i in 0..tau {
        let pdecom_i;
        // Getting the chall bytes of the correct tree
        let ith_tree_chall_as_bytes =
            get_chall_for_ith_tree(chall_as_bytes.clone(), i, t0, Fp_bit_len);
        if i < t0 {
            pdecom_i = open(&decom[i], ith_tree_chall_as_bytes, d0);
        } else {
            pdecom_i = open(&decom[i], ith_tree_chall_as_bytes, d1);
        }
        pdecom.push(pdecom_i);
    }
    pdecom
}

// line VOLE.V::2
pub(crate) fn vole_verify<Fp: PrimeFiniteField>(
    decom_delta: Pdecom,
    delta: Vec<Fp>,
    iv: IV,
    depth: usize,
    tree_idx: usize,
) -> (H1, Vec<Seed>) {
    let delta_as_bytes = chall_fp_vec_to_bytes_vec(&delta);

    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
    let ith_tree_delta_bytes = get_chall_for_ith_tree(delta_as_bytes, tree_idx, T0, Fp_bit_len);

    let (h, seed) = reconstruct(decom_delta.clone(), ith_tree_delta_bytes.clone(), iv, depth);

    // if tree_idx > 14 {
    //     println!(
    //         // "VOLE: {:?}, {:?}, {:?}, {:?}, {:?}",
    //         "VOLE: {:?}",
    //         // decom_delta.0,
    //         // ith_tree_delta_bytes,
    //         // iv,
    //         // depth,
    //         seed
    //     );
    // }

    (h, seed)
}

pub(crate) fn get_prime_ell_hat_len(l: usize) -> usize {
    l + 3
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    use crate::vole_prime::{
        self,
        all_but_one_vc::h1_on_coms,
        commit_reconstruct::vole_verify,
        // parameters::{Kc, Nc, D0, D1, N0, N1, T0, T1, TAU}
    };

    use crate::parameters::{D0, D1, KC, NC, T0, TAU};

    use super::{get_prime_ell_hat_len, vole_commit, vole_open, Commit};

    use crate::vole::crypto_primitives::IV;

    fn test_vole_commit_reconstruct<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let mut r: IV = [0; 16];
        let mut iv: IV = [0; 16];

        for idx in 0..16 {
            r[idx] = rand::thread_rng().gen_range(0..(1 << 8) - 1) as u8;
            iv[idx] = rand::thread_rng().gen_range(0..(1 << 8) - 1) as u8;
        }

        let ell_hat = get_prime_ell_hat_len(1);

        let Commit {
            com,
            decom,
            U1: _,
            P: _,
            V: _,
            C: _,
        }: vole_prime::commit_reconstruct::Commit<Fp> =
            vole_commit(r, iv, ell_hat, TAU, NC, KC, D0, D1);

        let mut chall: Vec<Fp> = Vec::with_capacity(TAU);
        for _ in 0..TAU {
            chall.push(
                Fp::try_from(rand::thread_rng().gen_range(0..(1 as u128) << 31) as u128)
                    .expect("err"),
            );
        }

        let pdecom = vole_open(chall.clone(), decom, TAU, T0, D0, D1);

        let mut all_tree_hi = Vec::with_capacity(TAU);
        for i in 0..TAU {
            if i < T0 {
                let (hi, _) = vole_verify(pdecom[i].clone(), chall.clone(), iv, D0, i);
                all_tree_hi.push(hi);
            } else {
                let (hi, _) = vole_verify(pdecom[i].clone(), chall.clone(), iv, D1, i);
                all_tree_hi.push(hi);
            }
        }
        let reconstructed_hash = h1_on_coms(&all_tree_hi);
        // line BAVC.Verify::16
        assert_eq!(com, reconstructed_hash);
    }

    #[test]
    fn test_vole_commit_reconstruct_f32p() {
        test_vole_commit_reconstruct::<F32p>();
    }
    #[test]
    fn test_vole_commit_reconstruct_f64p() {
        test_vole_commit_reconstruct::<F64p>();
    }
    #[test]
    fn test_vole_commit_reconstruct_frs127p() {
        test_vole_commit_reconstruct::<Frs127p>();
    }
    #[test]
    fn test_vole_commit_reconstruct_f128p() {
        test_vole_commit_reconstruct::<F128p>();
    }
    #[test]
    fn test_vole_commit_reconstruct_f256p() {
        test_vole_commit_reconstruct::<F256p>();
    }
}
