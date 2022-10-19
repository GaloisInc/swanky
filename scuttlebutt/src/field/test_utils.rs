use crate::field::{polynomial::Polynomial, FiniteField};
use generic_array::{ArrayLength, GenericArray};

pub(crate) fn make_polynomial<FE: FiniteField>(x: impl AsRef<[FE]>) -> Polynomial<FE> {
    let x = x.as_ref();
    Polynomial {
        constant: x[0],
        coefficients: x[1..].iter().cloned().collect(),
    }
}

pub(crate) fn make_polynomial_coefficients<FE: FiniteField, L: ArrayLength<FE>>(
    poly: &Polynomial<FE>,
) -> GenericArray<FE, L> {
    let mut slice = vec![FE::ZERO; L::USIZE];
    slice[0] = poly.constant;
    for (a, b) in slice[1..].iter_mut().zip(poly.coefficients.iter()) {
        *a = *b;
    }
    GenericArray::<FE, L>::from_slice(&slice[..]).clone()
}

macro_rules! test_field {
    ($tests_name:ident, $f:ty) => {
        mod $tests_name {
            use generic_array::typenum::Unsigned;
            use crate::ring::FiniteRing;
            use crate::field::FiniteField;
            use crate::field::test_utils::{make_polynomial, make_polynomial_coefficients};

            $crate::ring::test_ring!(ring_tests, $f);

            #[allow(unused_imports)]
            use proptest::prelude::*;
            fn any_fe() -> impl Strategy<Value=$f> {
                any::<u128>().prop_map(|seed| {
                    <$f as $crate::field::FiniteRing>::from_uniform_bytes(&seed.to_le_bytes())
                })
            }
            fn any_prime_fe() -> impl Strategy<Value=<$f as $crate::field::FiniteField>::PrimeField> {
                any::<u128>().prop_map(|seed| {
                    <<$f as $crate::field::FiniteField>::PrimeField as $crate::field::FiniteRing>
                        ::from_uniform_bytes(&seed.to_le_bytes())
                })
            }

            proptest! {
                #[test]
                fn multiplicative_inverse(a in any_fe()) {
                    if a != <$f>::ZERO {
                        let b = a.inverse();
                        prop_assert_eq!(a * b, <$f>::ONE);
                    }
                }
            }
            proptest! {
                #[test]
                fn polynomial_roundtrip(a in any_fe()) {
                    prop_assert_eq!(<$f>::from_polynomial_coefficients(a.to_polynomial_coefficients()), a);
                }
            }
            proptest! {
                #[test]
                fn polynomial_add(a in any_fe(), b in any_fe()) {
                    let mut poly = make_polynomial(a.to_polynomial_coefficients());
                    poly += &make_polynomial(b.to_polynomial_coefficients());
                    prop_assert_eq!(<$f>::from_polynomial_coefficients(make_polynomial_coefficients(&poly)), a + b);
                }
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(
                    std::env::var("PROPTEST_CASES")
                        .map(|x| x.parse().expect("PROPTEST_CASES is a number"))
                        .unwrap_or(15)
                ))]
                #[test]
                fn polynomial_mul(a in any_fe(), b in any_fe()) {
                    let mut poly = make_polynomial(a.to_polynomial_coefficients());
                    poly *= &make_polynomial(b.to_polynomial_coefficients());
                    let (_, remainder) = poly.divmod(&<$f>::polynomial_modulus());
                    prop_assert_eq!(
                        <$f>::from_polynomial_coefficients(make_polynomial_coefficients(&remainder)),
                        a * b
                    );
                }
            }

            proptest! {
                #[test]
                fn prime_field_lift_is_homomorphism(a in any_prime_fe(), b in any_prime_fe()) {
                    let lift: fn(<$f as FiniteField>::PrimeField) -> $f =
                        <<$f as FiniteField>::PrimeField as Into<$f>>::into;
                    prop_assert_eq!(lift(a) + lift(b), lift(a + b));
                    prop_assert_eq!(lift(a) * lift(b), lift(a * b));
                }
            }

            proptest! {
                #[test]
                fn lifted_polynomial_mul(a in any_fe(), b in any_prime_fe()) {
                    let mut poly = make_polynomial(a.to_polynomial_coefficients());
                    poly *= &make_polynomial(b.to_polynomial_coefficients());
                    let (_, remainder) = poly.divmod(&<$f>::polynomial_modulus());
                    prop_assert_eq!(
                        <$f>::from_polynomial_coefficients(make_polynomial_coefficients(&remainder)),
                        b * a
                    );
                }
            }

            #[test]
            fn polynomial_constants() {
                assert_eq!(
                    make_polynomial(<$f>::ZERO.to_polynomial_coefficients()),
                    $crate::field::Polynomial::zero()
                );
                assert_eq!(
                    make_polynomial(<$f>::ONE.to_polynomial_coefficients()),
                    $crate::field::Polynomial::one()
                );
            }
            proptest! {
                #[test]
                fn bit_decomposition_works(x in any_fe()) {
                    let decomp = x.bit_decomposition();
                    prop_assert_eq!(
                        decomp.len(),
                        <$f as FiniteField>::Degree::USIZE *
                            <<$f as FiniteField>::PrimeField as FiniteField>::NumberOfBitsInBitDecomposition::USIZE
                    );
                    let coeffs = x.to_polynomial_coefficients();
                    type PF = <$f as FiniteField>::PrimeField;
                    for (coeff_bits, coeff) in decomp.chunks_exact(<PF as FiniteField>::NumberOfBitsInBitDecomposition::USIZE).zip(coeffs) {
                        // This will equal 2 modulo PF. We couldn't do this for extension fields.
                        let two = PF::ONE + PF::ONE;
                        let mut pow_of_two = PF::ONE;
                        let mut rebuilt_coeff = PF::ZERO;
                        for bit in coeff_bits.iter().copied() {
                            if bit {
                                rebuilt_coeff += pow_of_two;
                            }
                            pow_of_two *= two;
                        }
                        prop_assert_eq!(rebuilt_coeff, coeff);
                    }
                }
            }
        }
    };
}
