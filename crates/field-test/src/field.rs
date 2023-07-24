use proptest::strategy::Strategy;
use swanky_field::{polynomial::Polynomial, FiniteField};

use crate::arbitrary_ring;

/// A proptest [`Strategy`] to generate a random polynomial.
pub fn arbitrary_polynomial<FE: FiniteField>() -> impl Strategy<Value = Polynomial<FE>> {
    (
        arbitrary_ring::<FE>(),
        proptest::collection::vec(arbitrary_ring::<FE>(), 0..15),
    )
        .prop_map(|(constant, coefficients)| Polynomial {
            constant,
            coefficients,
        })
}

/// Test that an implementation follows the finite field axioms.
///
/// Run it like `swanky_field_test::test_field!(field_tests, MyFunField)` where `field_tests` is an
/// arbitrary module name used to namespace the tests, and `MyFunField` is the field to test.
#[macro_export]
macro_rules! test_field {
    ($tests_name:ident, $fe:ty) => {
        mod $tests_name {
            use super::*;
            type FE = $fe;
            // We make tests a separate module, so that we can avoid the `use super::*;` from
            // polluting the tests namespace. We need the `use super::*;` above, because `$f` might
            // be an unqualified name in the super namespace.
            mod tests {
                use super::FE;
                use $crate::__internal_macro_exports::*;
                use proptest::prelude::*;
                use generic_array::{GenericArray, ArrayLength, typenum::Unsigned};
                use swanky_field::{Degree, FiniteField, FiniteRing, PrimeFiniteField, polynomial::Polynomial};
                use swanky_serialization::CanonicalSerialize;

                type PF = <FE as FiniteField>::PrimeField;

                $crate::test_ring!(ring_tests, FE);
                fn make_polynomial(x: impl AsRef<[PF]>) -> Polynomial<PF> {
                    let x = x.as_ref();
                    Polynomial {
                        constant: x[0],
                        coefficients: x[1..].iter().cloned().collect(),
                    }
                }

                fn make_polynomial_coefficients<L: ArrayLength<PF>>(
                    poly: &Polynomial<PF>,
                ) -> GenericArray<PF, L> {
                    let mut slice = vec![PF::ZERO; L::USIZE];
                    slice[0] = poly.constant;
                    for (a, b) in slice[1..].iter_mut().zip(poly.coefficients.iter()) {
                        *a = *b;
                    }
                    GenericArray::<PF, L>::from_slice(&slice[..]).clone()
                }

                fn any_fe() -> impl Strategy<Value = FE> {
                    $crate::arbitrary_ring::<FE>()
                }
                fn any_prime_fe() -> impl Strategy<Value = <FE as FiniteField>::PrimeField> {
                    $crate::arbitrary_ring::<<FE as FiniteField>::PrimeField>()
                }

                proptest! {
                    #[test]
                    fn crypto_bigint_into_int_consistent(a in any_prime_fe()) {
                        type PF = <FE as FiniteField>::PrimeField;
                        let wider_int = PF::into_int::<{PF::MIN_LIMBS_NEEDED + 1}>(&a);
                        let narrower_int = PF::into_int::<{PF::MIN_LIMBS_NEEDED}>(&a);
                        prop_assert_eq!(wider_int, narrower_int.resize())
                    }
                }
                proptest! {
                    #[test]
                    fn crypto_bigint_min_limbs_roundtrip(a in any_prime_fe()) {
                        type PF = <FE as FiniteField>::PrimeField;
                        let b = PF::try_from_int(PF::into_int::<{PF::MIN_LIMBS_NEEDED}>(&a)).unwrap();
                        prop_assert_eq!(a, b);
                    }
                }
                proptest! {
                    #[test]
                    fn crypto_bigint_min_limbs_1_roundtrip(a in any_prime_fe()) {
                        type PF = <FE as FiniteField>::PrimeField;
                        let b = PF::try_from_int(PF::into_int::<{PF::MIN_LIMBS_NEEDED + 1}>(&a)).unwrap();
                        prop_assert_eq!(a, b);
                    }
                }
                proptest! {
                    #[test]
                    fn crypto_bigint_min_limbs_2_roundtrip(a in any_prime_fe()) {
                        type PF = <FE as FiniteField>::PrimeField;
                        let b = PF::try_from_int(PF::into_int::<{PF::MIN_LIMBS_NEEDED + 2}>(&a)).unwrap();
                        prop_assert_eq!(a, b);
                    }
                }
                proptest! {
                    #[test]
                    fn multiplicative_inverse(a in any_fe()) {
                        if a != FE::ZERO {
                            let b = a.inverse();
                            prop_assert_eq!(a * b, FE::ONE);
                        }
                    }
                }
                proptest! {
                    #[test]
                    fn polynomial_roundtrip(a in any_fe()) {
                        prop_assert_eq!(FE::from_subfield(&a.decompose::<<FE as FiniteField>::PrimeField>()), a);
                    }
                }
                proptest! {
                    #[test]
                    fn polynomial_add(a in any_fe(), b in any_fe()) {
                        let mut poly = make_polynomial(a.decompose::<<FE as FiniteField>::PrimeField>());
                        poly += &make_polynomial(b.decompose::<<FE as FiniteField>::PrimeField>());
                        prop_assert_eq!(FE::from_subfield(&make_polynomial_coefficients(&poly)), a + b);
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
                        let mut poly = make_polynomial(a.decompose::<<FE as FiniteField>::PrimeField>());
                        poly *= &make_polynomial(b.decompose::<<FE as FiniteField>::PrimeField>());
                        let (_, remainder) = poly.divmod(&FE::polynomial_modulus());
                        prop_assert_eq!(
                            FE::from_subfield(&make_polynomial_coefficients(&remainder)),
                            a * b
                        );
                    }
                }

                proptest! {
                    #[test]
                    fn prime_field_lift_is_homomorphism(a in any_prime_fe(), b in any_prime_fe()) {
                        let lift: fn(<FE as FiniteField>::PrimeField) -> FE =
                            <<FE as FiniteField>::PrimeField as Into<FE>>::into;
                        prop_assert_eq!(lift(a) + lift(b), lift(a + b));
                        prop_assert_eq!(lift(a) * lift(b), lift(a * b));
                    }
                }

                proptest! {
                    #[test]
                    fn lifted_polynomial_mul(a in any_fe(), b in any_prime_fe()) {
                        let mut poly = make_polynomial(a.decompose::<<FE as FiniteField>::PrimeField>());
                        poly *= &make_polynomial(b.decompose::<<FE as FiniteField>::PrimeField>());
                        let (_, remainder) = poly.divmod(&<FE>::polynomial_modulus());
                        prop_assert_eq!(
                            <FE>::from_subfield(&make_polynomial_coefficients(&remainder)),
                            b * a
                        );
                    }
                }

                #[test]
                fn polynomial_constants() {
                    assert_eq!(
                        make_polynomial(<FE>::ZERO.decompose::<<FE as FiniteField>::PrimeField>()),
                        Polynomial::zero()
                    );
                    assert_eq!(
                        make_polynomial(<FE>::ONE.decompose::<<FE as FiniteField>::PrimeField>()),
                        Polynomial::one()
                    );
                }
                proptest! {
                    #[test]
                    fn bit_decomposition_works(x in any_fe()) {
                        let decomp = x.bit_decomposition();
                        prop_assert_eq!(
                            decomp.len(),
                            Degree::<FE>::USIZE *
                                <<FE as FiniteField>::PrimeField as FiniteField>::NumberOfBitsInBitDecomposition::USIZE
                        );
                        let coeffs = x.decompose::<<FE as FiniteField>::PrimeField>();
                        type PF = <FE as FiniteField>::PrimeField;
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
                mod polynomials {
                    use super::*;
                    fn any_poly() -> impl Strategy<Value=Polynomial<FE>> {
                        $crate::arbitrary_polynomial::<FE>()
                    }
                    #[test]
                    fn test_degree() {
                        assert_eq!(Polynomial::<FE>::zero().degree(), 0);
                        assert_eq!(Polynomial::<FE>::one().degree(), 0);
                        assert_eq!(Polynomial::<FE>::x().degree(), 1);
                        assert_eq!(
                            (Polynomial {
                                constant: FE::ZERO,
                                coefficients: vec![FE::ZERO, FE::ZERO],
                            })
                            .degree(),
                            0
                        );
                        assert_eq!(
                            (Polynomial {
                                constant: FE::ZERO,
                                coefficients: vec![FE::ZERO, FE::ZERO, FE::ONE, FE::ZERO, FE::ZERO, FE::ZERO],
                            })
                            .degree(),
                            3
                        );
                    }
                    fn test_x_values() -> impl Strategy<Value=Vec<FE>> {
                        proptest::collection::vec(any_fe(), 10)
                    }
                    proptest! {
                        #[test]
                        fn test_addition(
                            a in any_poly(),
                            b in any_poly(),
                            xs in test_x_values(),
                        ) {
                            let mut out = a.clone();
                            out += &b;
                            for x in xs.into_iter() {
                                prop_assert_eq!(out.eval(x), a.eval(x) + b.eval(x));
                            }
                        }
                    }
                    proptest! {
                        #[test]
                        fn test_subtraction(
                            a in any_poly(),
                            b in any_poly(),
                            xs in test_x_values(),
                        ) {
                            let mut out = a.clone();
                            out -= &b;
                            for x in xs.into_iter() {
                                prop_assert_eq!(out.eval(x), a.eval(x) - b.eval(x));
                            }
                        }
                    }
                    proptest! {
                        #[test]
                        fn test_multiplication(
                            a in any_poly(),
                            b in any_poly(),
                            xs in test_x_values(),
                        ) {
                            let mut out = a.clone();
                            out *= &b;
                            for x in xs.into_iter() {
                                prop_assert_eq!(out.eval(x), a.eval(x) * b.eval(x));
                            }
                        }
                    }
                    proptest! {
                        #[test]
                        fn test_scalar_multiplication(
                            a in any_poly(),
                            b in any_fe(),
                            xs in test_x_values(),
                        ) {
                            let mut out = a.clone();
                            out *= b;
                            for x in xs.into_iter() {
                                prop_assert_eq!(out.eval(x), a.eval(x) * b);
                            }
                        }
                    }
                    proptest! {
                        #[test]
                        fn test_interpolation(
                            mut points in proptest::collection::vec((any_fe(), any_fe()), 1..10)
                        ) {
                            points.sort_unstable_by_key(|(x, _)| x.to_bytes());
                            points.dedup_by_key(|(x, _)| *x);
                            if !points.is_empty() {
                                let poly = Polynomial::interpolate(&points);
                                for (x, y) in points {
                                    prop_assert_eq!(poly.eval(x), y);
                                }
                            }
                        }
                    }
                    proptest! {
                        #[test]
                        fn test_divmod(a in any_poly(), mut b in any_poly()) {
                            if b != Polynomial::<FE>::zero() {
                                let (q, r) = a.divmod(&b);
                                prop_assert!(
                                    r == Polynomial::zero() || r.degree() < b.degree(),
                                    "{:?} {:?}",
                                    r,
                                    b
                                );
                                b *= &q;
                                b += &r;
                                // a = b*q + r
                                prop_assert_eq!(a, b);
                            }
                        }
                    }
                    // TODO: test newton polynomials
                }
            }
        }
    };
}
