use swanky_field::PrimeFiniteField;

// use crate::prime::parameters::MAX_LIMBS_SUPPORTED;
use crate::parameters::MAX_LIMBS_SUPPORTED;

pub(crate) fn fp_a_gt_fp_b<Fp: PrimeFiniteField>(a: Fp, b: Fp) -> bool {
    let a_bit_vec = a.bit_decomposition().to_vec();
    let b_bit_vec = b.bit_decomposition().to_vec();
    assert_eq!(a_bit_vec.len(), b_bit_vec.len());

    // TODO: Make this constant time!!
    for i in (0..a_bit_vec.len()).rev() {
        if a_bit_vec[i] == b_bit_vec[i] {
            continue;
        }
        if a_bit_vec[i] == false && b_bit_vec[i] == true {
            return false;
        }
        if a_bit_vec[i] == true && b_bit_vec[i] == false {
            return true;
        }
    }
    false
}

pub(crate) fn fp_to_u64arr<Fp: PrimeFiniteField>(input: Fp) -> Vec<u64> {
    let input_u64arr: [u64; MAX_LIMBS_SUPPORTED] = Fp::as_int(&input).to_words();

    let mut ret_u64arr = vec![0u64; MAX_LIMBS_SUPPORTED];
    for (idx, elem) in input_u64arr.into_iter().enumerate() {
        ret_u64arr[idx] = elem;
    }

    return ret_u64arr[..Fp::MIN_LIMBS_NEEDED].to_vec();
}

pub(crate) fn get_vec_u8_bit(input: Vec<u8>, byteidx: usize, bitidx: usize) -> u8 {
    return (input[byteidx] >> bitidx) & 0x01;
}

/*
stupid test cases
*/
#[cfg(test)]
mod test {
    use std::sync::Once;

use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};

    use crate::vole_prime::utils::{fp_a_gt_fp_b, fp_to_u64arr, get_vec_u8_bit};

    static INIT: Once = Once::new();
    fn init_logger() {
        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .try_init();
        });
    }

    #[test]
    fn test_get_bit() {

        // if log-level `RUST_LOG` not already set, then set to info
        init_logger();

        let input = vec![0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        assert_eq!(get_vec_u8_bit(input, 9, 1), 1);
    }

    #[test]
    fn test_fp_to_u64arr_fp128() {

        // if log-level `RUST_LOG` not already set, then set to info
        init_logger();

        const GEN: u64 = 5;
        let a = F128p::GENERATOR * F128p::try_from(100 as u128).expect("err");
        let b = F128p::GENERATOR * F128p::try_from(200 as u128).expect("err");
        let c = vec![GEN * 100 + GEN * 200 as u64, 0];

        assert_eq!(fp_to_u64arr(a + b), c);
    }

    /// The a > b tests
    fn test_a_gt_b<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {

        // if log-level `RUST_LOG` not already set, then set to info
        init_logger();

        let fp_a = Fp::try_from(6).unwrap_or_default();
        let fp_b = Fp::try_from(10).unwrap_or_default();
        assert_eq!(fp_a_gt_fp_b(fp_a, fp_b), false);

        let fp_a = Fp::try_from(10).unwrap_or_default();
        let fp_b = Fp::try_from(6).unwrap_or_default();
        assert_eq!(fp_a_gt_fp_b(fp_a, fp_b), true);

        let fp_a = Fp::try_from(6).unwrap_or_default();
        let fp_b = Fp::try_from(6).unwrap_or_default();
        assert_eq!(fp_a_gt_fp_b(fp_a, fp_b), false);
    }

    #[test]
    fn test_a_gt_b_f32p() {
        test_a_gt_b::<F128p>();
    }
    #[test]
    fn test_a_gt_b_f64p() {
        test_a_gt_b::<F64p>();
    }
    #[test]
    fn test_a_gt_b_frs127p() {
        test_a_gt_b::<Frs127p>();
    }
    #[test]
    fn test_a_gt_b_f128p() {
        test_a_gt_b::<F128p>();
    }
    #[test]
    fn test_a_gt_b_f256p() {
        test_a_gt_b::<F256p>();
    }
}
