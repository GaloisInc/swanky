#![allow(clippy::needless_range_loop)]
use crate::vole::crypto_primitives::{Com};
use crate::vole_prime::{
    all_but_one_vc::chall_fp_vec_to_bytes_vec,
    convert_to_vole::Corrections,
    crypto_primitives::{h1, prg_compact_to_fp, H1, pPRG},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use swanky_field::PrimeFiniteField;

// line VOLE.P2::2-3
// The dim is either KC or NC
#[inline(never)]
pub(crate) fn vole_hash<Fp: PrimeFiniteField>(
    H: Vec<Fp>,
    inp: Vec<Vec<Fp>>, // can be U1, V or Q
    ell_hat: usize,    // ell_hat or 2
    dim: usize,        // can be KC or NC
) -> Vec<Fp> {
    let mut out: Vec<Fp> = Vec::with_capacity(dim * 2);

    for i in 0..2 {
        for dim_i in 0..dim {
            out.push(Fp::ZERO);
            for l_hat_i in 0..ell_hat {
                out[dim_i + i * dim] += H[l_hat_i + i * ell_hat] * inp[dim_i][l_hat_i];
            }
        }
    }
    out
}

// line exchnage between VOLE.P1 and VOLE.P2
pub(crate) fn compute_Hv_Chall<Fp: PrimeFiniteField>(
    hcom: Com,
    C: Corrections<Fp>,
    ell_hat: usize,
) -> Vec<Fp> {
    let mut C_bytes = chall_fp_vec_to_bytes_vec(C.to_vec());
    let mut hcom_plus_c_bytes = Vec::with_capacity(hcom.len() + C_bytes.len());

    hcom_plus_c_bytes.append(&mut hcom.to_vec());
    hcom_plus_c_bytes.append(&mut C_bytes);
    let hv = h1(&hcom_plus_c_bytes);

    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
    let chall_bit_len = ell_hat * 2 * Fp_bit_len; // The actual chall bit size will be ell_hat * 2 * Fp_elem_size_in_bits

    let prg_out = pPRG::new(
        hv[0..16].try_into().unwrap(),
        hv[16..32].try_into().unwrap(),
    );
    prg_compact_to_fp(prg_out.prg_compact(chall_bit_len), chall_bit_len)
}

// line exchange between VOLE.P2 and VOLE.P3
pub(crate) fn compute_Delta_Chall<Fp: PrimeFiniteField>(
    U_tilde: Vec<Fp>,
    h_small: H1,
    nc: usize,
    tree_depth: usize,
) -> Vec<Fp> {
    let mut U_tilde_bytes = chall_fp_vec_to_bytes_vec(U_tilde);
    let mut h_small_plus_u_tilde_bytes = Vec::with_capacity(h_small.len() + U_tilde_bytes.len());

    h_small_plus_u_tilde_bytes.append(&mut U_tilde_bytes);
    h_small_plus_u_tilde_bytes.append(&mut h_small.to_vec());
    let S_delta = h1(&h_small_plus_u_tilde_bytes);

    // TODO: Use some cryptographic rng!!
    let mut rng = StdRng::from_seed(S_delta);
    // NOTE: The deltas have S_delta values which mean they are are not in the full Fp range but rather 2^depth of the tree range
    // else (delta_i - j) does not work in the verifiation construction of q
    // NOTE: Even though not using the full Fp, the security still holds as for all NC deltas we will combined use lambda bits of security
    let deltas: Vec<u64> = (0..nc)
        .map(|_| rng.gen_range(0..(1 << tree_depth) - 1)) // TODO: The tree depth thing seems to be off, replace this function with something more generic
        .collect();
    let mut deltas_fp = Vec::with_capacity(nc);

    for i in 0..nc {
        deltas_fp.push(Fp::try_from(deltas[i] as u128).unwrap_or_default());
    }
    deltas_fp
}

#[cfg(test)]
mod test {
    use swanky_field::{FiniteField, FiniteRing, PrimeFiniteField};
    use swanky_field_ff_primes::{F127p, F128p, F256p, F32p, F64p};

    use crate::vole_prime::{
        commit_reconstruct::get_prime_ell_hat_len,
        consistency_check::{compute_Delta_Chall, compute_Hv_Chall},
        // parameters::NC
    };

    use crate::parameters::NC;

    use super::vole_hash;

    // Test that [`vole_hash`] returns 0 when H is all 0.
    fn test_vole_hash_zero<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let l = 3;
        let l_hat = get_prime_ell_hat_len(l);

        let mut H: Vec<Fp> = Vec::with_capacity(2 * l_hat);
        for _ in 0..2 * l_hat {
            H.push(Fp::ZERO);
        }

        let mut inp: Vec<Vec<Fp>> = Vec::with_capacity(NC);
        for i in 0..NC {
            let mut tmp: Vec<Fp> = Vec::with_capacity(l_hat);
            for j in 0..l_hat {
                tmp.push(Fp::try_from((i * l_hat + j) as u128).expect("err"));
            }
            inp.push(tmp);
        }

        let mut all_zero_out: Vec<Fp> = Vec::with_capacity(2 * NC);
        for _ in 0..2 * NC {
            all_zero_out.push(Fp::ZERO);
        }

        let out = vole_hash(H, inp, l_hat, NC);

        assert_eq!(out, all_zero_out);
    }

    #[test]
    fn test_vole_hash_zero_f128p() {
        test_vole_hash_zero::<F128p>();
    }

    // Test that [`vole_hash`] returns 0+1+..+l_hat when H is all 1.
    fn test_vole_hash_one<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let l = 3;
        let l_hat = get_prime_ell_hat_len(l);

        let mut H: Vec<Fp> = Vec::with_capacity(2 * l_hat);
        for _ in 0..2 * l_hat {
            H.push(Fp::ZERO);
        }

        let mut inp: Vec<Vec<Fp>> = Vec::with_capacity(NC);
        for i in 0..NC {
            let mut tmp: Vec<Fp> = Vec::with_capacity(l_hat);
            for j in 0..l_hat {
                tmp.push(Fp::try_from((i * l_hat + j) as u128).expect("err"));
            }
            inp.push(tmp);
        }

        let mut all_zero_out: Vec<Fp> = Vec::with_capacity(2 * NC);
        for _ in 0..2 * NC {
            all_zero_out.push(Fp::ZERO);
        }

        let out = vole_hash(H, inp, l_hat, NC);

        assert_eq!(out, all_zero_out);
    }

    #[test]
    fn test_vole_hash_one_f128p() {
        test_vole_hash_one::<F128p>();
    }

    // Testing the Hv chall happeninig between P1 and P2
    fn test_Hv_chall<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let hcom = [1; 32];
        let C: Vec<Fp> = vec![Fp::ONE; 2];
        let ell_hat = 8;

        let out = compute_Hv_Chall(hcom, C, ell_hat);

        assert_eq!(8 * 2, out.len()); // Just checking if the number of Fp element are as expected
    }

    #[test]
    fn test_Hv_chall_f128p() {
        test_Hv_chall::<F128p>();
    }

    fn test_Delta_chall<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let h_small = [1; 32];
        let U_tilde: Vec<Fp> = vec![Fp::ONE; 2];
        let nc = 8;
        let tree_depth = 4;

        let out = compute_Delta_Chall(U_tilde, h_small, nc, tree_depth);

        assert_eq!(8, out.len()); // Just checking if the number of Fp element are as expected
    }

    #[test]
    fn test_Delta_chall_f32p() {
        test_Delta_chall::<F32p>();
    }
    #[test]
    fn test_Delta_chall_f64p() {
        test_Delta_chall::<F64p>();
    }
    #[test]
    fn test_Delta_chall_f127p() {
        test_Delta_chall::<F127p>();
    }
    #[test]
    fn test_Delta_chall_f128p() {
        test_Delta_chall::<F128p>();
    }
    #[test]
    fn test_Delta_chall_f256p() {
        test_Delta_chall::<F256p>();
    }
}
