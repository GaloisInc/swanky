use std::ops::Div;

use crypto_bigint::{ArrayEncoding, Limb, NonZero, Uint, U512};
use proptest::{bits::u64};
use swanky_field::PrimeFiniteField;
use swanky_field_fft::{self, fft2, fft2_in_place, fft2_inverse};

use crate::parameters::{MAX_LIMBS_SUPPORTED, NC};

pub(crate) fn compute_nth_root_of_unity<Fp: PrimeFiniteField>(N: usize) -> Fp {
    let primitive_element = Fp::GENERATOR;
    let order = Fp::ZERO - Fp::ONE; // prime_mod - 1

    let order_uint: crypto_bigint::Uint<MAX_LIMBS_SUPPORTED> = order.as_int();
    let N_uint: NonZero<Uint<8>> = NonZero::new(U512::from_u64(N as u64)).expect("N must be non-zero");
    let exponent_uint = order_uint.rem(&N_uint); // should divide with 0 rem
    assert_eq!(exponent_uint, U512::from_u64(0));

    let exponent = Fp::try_from_int(exponent_uint).expect("failed from U512 to Fp");

    let exponent_bits = Fp::bit_decomposition(&exponent);

    let mut base: Fp = primitive_element.clone();
    let mut Nth_root_of_unity = Fp::ONE;

    for bit in exponent_bits {
        // while exponent != 0 {
        // TODO: make it constant time or get rekt by the side-channel boys!!!!!!!
        if bit == true {
            // if exponent & 1 == 1 {
            Nth_root_of_unity *= base;
        }
        base *= base;
        // exponent = exponent >> 1;
    }

    let mut Nth_root_of_unity_tmp = Fp::ONE;

    base = Nth_root_of_unity.clone();
    let test = Fp::try_from(N as u128).unwrap_or_default();
    let test_bit = Fp::bit_decomposition(&test);
    for bit in test_bit {
        // TODO: make it constant time or get rekt by the side-channel boys!!!!!!!
        if bit == true {
            Nth_root_of_unity_tmp *= base;
        }
        base *= base;
    }

    assert_eq!(Nth_root_of_unity_tmp, Fp::ONE);

    Nth_root_of_unity
}

pub(crate) fn reed_solomon_encode<Fp: PrimeFiniteField + swanky_field_fft::FieldForFFT<2>>(
    Kc: usize,
    Nc: usize,
    x: Vec<Fp>,
    ell_hat: usize,
    N: usize,
) -> Vec<Fp> {
    assert!(Kc <= Nc);
    assert!(N >= Nc);
    assert!(N % Kc == 0);
    let stride = N / Kc;

    let omega: Fp = compute_nth_root_of_unity(N);
    assert!(omega.pow(N as u128) == Fp::ONE);
    let omega_0 = omega.pow((N / Kc) as u128);

    // The IFFT
    let mut coeff: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    for ell_hat_i in 0..ell_hat {
        let mut x_kc_elem: Vec<Fp> = Vec::with_capacity(Kc);
        for kc_i in 0..Kc {
            x_kc_elem.push(x[kc_i * ell_hat + ell_hat_i]);
        }
        coeff.push(fft2_inverse(&x_kc_elem, omega_0));

        let mut check = coeff[ell_hat_i].clone();
        check.resize(Kc, Fp::ZERO);
        assert_eq!(fft2(&check, omega_0), x_kc_elem);
    }

    // The FFT
    let mut coeffeval: Vec<Vec<Fp>> = Vec::with_capacity(ell_hat);
    let mut zero_pads: Vec<Fp> = Vec::with_capacity(N - Kc);
    zero_pads.resize(N - Kc, Fp::ZERO);

    for ell_hat_i in 0..ell_hat {
        coeff[ell_hat_i].resize(N, Fp::ZERO);

        coeffeval.push(fft2(&coeff[ell_hat_i], omega));

        assert_eq!(coeffeval[ell_hat_i].len(), N);
        assert_eq!(fft2_inverse(&coeffeval[ell_hat_i], omega), coeff[ell_hat_i]);
    }

    for i in 0..Kc {
        let idx = i * stride;
        for ell_hat_i in 0..ell_hat {
            assert_eq!(coeffeval[ell_hat_i][idx], x[i * ell_hat + ell_hat_i]);
        }
    }

    let mut C: Vec<Fp> = Vec::with_capacity(ell_hat * N);

    // message part
    for nckc_i in 0..Kc {
        for ell_hat_i in 0..ell_hat {
            C.push(coeffeval[ell_hat_i][nckc_i * stride]);
        }
    }

    // partity part
    for nckc_i in 0..N {
        if (nckc_i % stride != 0) {
            for ell_hat_i in 0..ell_hat {
                C.push(coeffeval[ell_hat_i][nckc_i]);
            }
        }
    }

    C
}

#[cfg(test)]
mod test {
    use swanky_field::{FiniteField, FiniteRing, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F384p, F400p, F61p, F64p};
    use swanky_field_fft::{fft2, fft2_inverse};

    use super::compute_nth_root_of_unity;

    /// Just checking the basic kth root of unity
    fn test_root_of_unity<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let n = 16;
        let omega: Fp = compute_nth_root_of_unity(n);
        // alpha ^ (prime_mod-1 / k) = omega, for any k that divides prime_mod-1, and omega is the root of unity
        // and omega ^ n = 1, is the n^th root of unity
        assert_eq!(omega.pow(n as u128), Fp::ONE);
    }

    #[test]
    fn test_root_of_unity_f32p() {
        test_root_of_unity::<F32p>();
    }
    #[test]
    fn test_root_of_unity_f64p() {
        test_root_of_unity::<F64p>();
    }
    #[test]
    fn test_root_of_unity_frs127p() {
        test_root_of_unity::<Frs127p>();
    }
    #[test]
    fn test_root_of_unity_f128p() {
        test_root_of_unity::<F128p>();
    }
    #[test]
    fn test_root_of_unity_f256p() {
        test_root_of_unity::<F256p>();
    }
}
