use crate::field::{polynomial::Polynomial, FiniteField};
use generic_array::{ArrayLength, GenericArray};
macro_rules! test_associativity {
    ($name:ident, $arbitrary_f:ty, $op:ident) => {
        #[quickcheck]
        fn $name(a: $arbitrary_f, b: $arbitrary_f, c: $arbitrary_f) -> bool {
            let a = a.0;
            let b = b.0;
            let c = c.0;
            a.$op(b).$op(c) == a.$op(b.$op(c))
        }
    };
}

macro_rules! test_commutativity {
    ($name:ident, $arbitrary_f:ty, $op:ident) => {
        #[quickcheck]
        fn $name(a: $arbitrary_f, b: $arbitrary_f) -> bool {
            let a = a.0;
            let b = b.0;
            a.$op(b) == b.$op(a)
        }
    };
}

macro_rules! test_identity {
    ($name:ident, $arbitrary_f:ty, $op:ident, $elem:expr) => {
        #[quickcheck]
        fn $name(a: $arbitrary_f) -> bool {
            let a = a.0;
            a.$op($elem) == a
        }
    };
}

macro_rules! test_assign {
    ($name:ident, $arbitrary_f:ty, $op:ident, $assign_op:ident) => {
        #[quickcheck]
        fn $name(a: $arbitrary_f, b: $arbitrary_f) -> bool {
            let a = a.0;
            let b = b.0;
            let mut out = a;
            out.$assign_op(b);
            out == a.$op(b)
        }
    };
}

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
    let mut slice = vec![FE::zero(); L::USIZE];
    slice[0] = poly.constant;
    for (a, b) in slice[1..].iter_mut().zip(poly.coefficients.iter()) {
        *a = *b;
    }
    GenericArray::<FE, L>::from_slice(&slice[..]).clone()
}

macro_rules! test_field {
    ($tests_name:ident, $f:ty) => {
        mod $tests_name {
            use super::*;
            use crate::field::test_utils::{make_polynomial, make_polynomial_coefficients};
            use quickcheck::Arbitrary;
            use quickcheck_macros::quickcheck;
            use std::ops::{Add, Mul, Sub};
            #[derive(Clone, Debug)]
            struct ArbitraryF($f);
            impl Arbitrary for ArbitraryF {
                fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
                    ArbitraryF(<$f>::random(g))
                }
            }
            test_associativity!(additive_associativity, ArbitraryF, add);
            test_associativity!(multiplicative_associativity, ArbitraryF, mul);

            test_commutativity!(additive_commutativity, ArbitraryF, add);
            test_commutativity!(multiplicative_commutativity, ArbitraryF, mul);

            test_identity!(additive_identity, ArbitraryF, add, <$f>::zero());
            test_identity!(multiplicative_identity, ArbitraryF, mul, <$f>::one());

            #[quickcheck]
            fn additive_inverse(a: ArbitraryF) -> bool {
                let a = a.0;
                let b = -a;
                a + b == <$f>::zero()
            }
            #[quickcheck]
            fn multiplicative_inverse(a: ArbitraryF) -> bool {
                let a = a.0;
                if a == <$f>::zero() {
                    return true;
                }
                let b = a.inverse();
                a * b == <$f>::one()
            }

            test_assign!(add_assign, ArbitraryF, add, add_assign);
            test_assign!(sub_assign, ArbitraryF, sub, sub_assign);
            test_assign!(mul_assign, ArbitraryF, mul, mul_assign);

            #[quickcheck]
            fn sub_and_neg(a: ArbitraryF, b: ArbitraryF) -> bool {
                let a = a.0;
                let b = b.0;
                a - b == a + (-b)
            }

            #[quickcheck]
            fn distributive(a: ArbitraryF, b: ArbitraryF, c: ArbitraryF) -> bool {
                let a = a.0;
                let b = b.0;
                let c = c.0;
                a * (b + c) == (a * b) + (a * c)
            }

            #[quickcheck]
            fn serialize(a: ArbitraryF) -> bool {
                let a = a.0;
                let buf = a.to_bytes();
                a == <$f>::from_bytes(&buf).unwrap()
            }

            #[quickcheck]
            fn test_power(a: ArbitraryF) {
                assert_eq!(a.0.pow(0), <$f>::one());
                if a.0 != <$f>::zero() {
                    assert_eq!(a.0.pow(<$f>::MULTIPLICATIVE_GROUP_ORDER), <$f>::one());
                } else {
                    assert_eq!(a.0.pow(<$f>::MULTIPLICATIVE_GROUP_ORDER), <$f>::zero());
                }
            }

            #[quickcheck]
            fn polynomial_roundtrip(a: ArbitraryF) -> bool {
                <$f>::from_polynomial_coefficients(a.0.to_polynomial_coefficients()) == a.0
            }

            fn prop_polynomial_add(a: $f, b: $f) -> bool {
                let mut poly = make_polynomial(a.to_polynomial_coefficients());
                poly += &make_polynomial(b.to_polynomial_coefficients());
                <$f>::from_polynomial_coefficients(make_polynomial_coefficients(&poly)) == a + b
            }

            #[quickcheck]
            fn polynomial_add(a: ArbitraryF, b: ArbitraryF) -> bool {
                prop_polynomial_add(a.0, b.0)
            }

            fn prop_polynomial_mul(a: $f, b: $f) -> bool {
                let mut poly = make_polynomial(a.to_polynomial_coefficients());
                poly *= &make_polynomial(b.to_polynomial_coefficients());
                let (_, remainder) = poly.divmod(&<$f>::reduce_multiplication_over());
                <$f>::from_polynomial_coefficients(make_polynomial_coefficients(&remainder))
                    == a * b
            }

            #[quickcheck]
            fn polynomial_mul(a: ArbitraryF, b: ArbitraryF) -> bool {
                prop_polynomial_mul(a.0, b.0)
            }

            #[test]
            fn polynomial_constants() {
                assert_eq!(
                    make_polynomial(<$f>::zero().to_polynomial_coefficients()),
                    Polynomial::zero()
                );
                assert_eq!(
                    make_polynomial(<$f>::one().to_polynomial_coefficients()),
                    Polynomial::one()
                );
            }
        }
    };
}
