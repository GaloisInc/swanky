#![allow(clippy::needless_range_loop)]

use crate::vole_prime::crypto_primitives::{pPRG, prg_compact_to_fp};

use crate::vole::crypto_primitives::{Seed, IV};

use swanky_field::PrimeFiniteField;

pub type Corrections<Fp> = Vec<Fp>;

pub(crate) fn convert_to_vole<Fp: PrimeFiniteField>(
    seeds: Vec<Seed>,
    iv: IV,
    ell_hat: usize,
    tree_depth: usize,
) -> (Vec<Fp>, Vec<Fp>) {
    assert_eq!(seeds.len().trailing_zeros() as usize, tree_depth); // Calling training zeros should be fine as seeds.len() is always 1 << some_n
    let N_i = 1 << tree_depth;

    assert!(N_i <= 1 << 32); // NOTE: Let's limit us to max tree depth of 32, I guess that's alright

    let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
    assert_ne!(Fp_bit_len, 0);

    let mut u: Vec<Fp> = vec![Fp::ZERO; ell_hat];
    let mut v: Vec<Fp> = vec![Fp::ZERO; ell_hat];
    let prg_bit_out_len = ell_hat * Fp_bit_len;

    // line VOLE.P1::4-5
    for j in 0..N_i {
        let prg_out = pPRG::new(seeds[j], iv);
        let out = prg_compact_to_fp(prg_out.prg_compact(prg_bit_out_len), prg_bit_out_len); // vec of size ell_hat returned

        // if j == 0 {
        //     println!("OUT: {:?}, {:?}", out, seeds[j]);
        // }

        let Fp_j = Fp::try_from(j as u128).unwrap_or_default();
        for Fp_elem_idx in 0..ell_hat {
            u[Fp_elem_idx] += out[Fp_elem_idx];
            v[Fp_elem_idx] -= Fp_j * out[Fp_elem_idx];
        }
    }

    (u, v)
}

#[cfg(test)]
mod test {

    use super::convert_to_vole;
    use crate::vole_prime::convert_to_vole::Seed;
    use rand::Rng;
    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    fn test_convert_to_vole<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        for ell_hat in 1..3 {
            for depth in (2..16).step_by(6) {
                let seed_len = 1 << depth;
                let mut seeds: Vec<Seed> = Vec::with_capacity(seed_len);
                let mut iv = [0u8; 16];

                let mut seed = [0u8; 16];
                for _ in 0..seed_len {
                    for seed_idx in 0..16 {
                        seed[seed_idx] = rand::thread_rng().gen_range(0..(1 << 8) - 1) as u8;
                    }
                    seeds.push(seed);
                }

                for idx in 0..16 {
                    iv[idx] = rand::thread_rng().gen_range(0..(1 << 8) - 1) as u8;
                }

                let (u, v) = convert_to_vole::<Fp>(seeds, iv, ell_hat, depth);

                assert_eq!(u.len(), ell_hat);
                assert_eq!(v.len(), ell_hat);
            }
        }
    }

    #[test]
    fn test_convert_to_vole_f32p() {
        test_convert_to_vole::<F32p>();
    }
    #[test]
    fn test_convert_to_vole_f64p() {
        test_convert_to_vole::<F64p>();
    }
    #[test]
    fn test_convert_to_vole_frs127p() {
        test_convert_to_vole::<Frs127p>();
    }
    #[test]
    fn test_convert_to_vole_f128p() {
        test_convert_to_vole::<F128p>();
    }
    #[test]
    fn test_convert_to_vole_f256p() {
        test_convert_to_vole::<F256p>();
    }
}
