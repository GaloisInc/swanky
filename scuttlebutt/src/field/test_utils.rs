use crate::field::{polynomial::Polynomial, FiniteField};
use generic_array::{ArrayLength, GenericArray};

macro_rules! test_associativity {
    ($name:ident, $any_fe:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_fe(), b in $any_fe(), c in $any_fe()) {
                assert_eq!(a.$op(b).$op(c), a.$op(b.$op(c)));
            }
        }
    };
}

macro_rules! test_commutativity {
    ($name:ident, $any_fe:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_fe(), b in $any_fe()) {
                assert_eq!(a.$op(b), b.$op(a));
            }
        }
    };
}

macro_rules! test_identity {
    ($name:ident, $any_fe:ident, $op:ident, $elem:expr) => {
        proptest! {
            #[test]
            fn $name(a in $any_fe()) {
                assert_eq!(a.$op($elem), a);
            }
        }
    };
}

macro_rules! test_assign {
    ($name:ident, $any_fe:ident, $op:ident, $assign_op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_fe(), b in $any_fe()) {
                let mut out = a;
                out.$assign_op(b);
                assert_eq!(out, a.$op(b));
            }
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
            use super::*;
            use crate::field::test_utils::{make_polynomial, make_polynomial_coefficients};
            #[allow(unused_imports)]
            use proptest::prelude::*;
            use std::ops::{Add, Mul, Sub};
            fn any_fe() -> impl Strategy<Value=$f> {
                // TODO: this is _totally_ cheating, and we should probably do something more proper.
                any::<u128>().prop_map(|seed| {
                    use rand::SeedableRng;
                    let mut rng = crate::AesRng::from_seed(crate::Block::from(seed));
                    <$f>::random(&mut rng)
                })
            }
            test_associativity!(additive_associativity, any_fe, add);
            test_associativity!(multiplicative_associativity, any_fe, mul);

            test_commutativity!(additive_commutativity, any_fe, add);
            test_commutativity!(multiplicative_commutativity, any_fe, mul);

            test_identity!(additive_identity, any_fe, add, <$f>::ZERO);
            test_identity!(multiplicative_identity, any_fe, mul, <$f>::ONE);

            test_assign!(add_assign, any_fe, add, add_assign);
            test_assign!(sub_assign, any_fe, sub, sub_assign);
            test_assign!(mul_assign, any_fe, mul, mul_assign);

            proptest! {
                #[test]
                fn additive_inverse(a in any_fe()) {
                    let b = -a;
                    assert_eq!(a + b, <$f>::ZERO);
                }
            }
            proptest! {
                #[test]
                fn multiplicative_inverse(a in any_fe()) {
                    if a != <$f>::ZERO {
                        let b = a.inverse();
                        assert_eq!(a * b, <$f>::ONE);
                    }
                }
            }
            proptest! {
                #[test]
                fn sub_and_neg(a in any_fe(), b in any_fe()) {
                    assert_eq!(a - b, a + (-b));
                }
            }
            proptest! {
                #[test]
                fn distributive(a in any_fe(), b in any_fe(), c in any_fe()) {
                    assert_eq!(a * (b + c), (a * b) + (a * c));
                }
            }
            proptest! {
                #[test]
                fn serialize(a in any_fe()) {
                    let buf = a.to_bytes();
                    assert_eq!(a, <$f>::from_bytes(&buf).unwrap());
                }
            }
            proptest! {
                #[test]
                fn test_power(a in any_fe()) {
                    assert_eq!(a.pow(0), <$f>::ONE);
                    if a != <$f>::ZERO {
                        assert_eq!(a.pow(<$f>::MULTIPLICATIVE_GROUP_ORDER), <$f>::ONE);
                    } else {
                        assert_eq!(a.pow(<$f>::MULTIPLICATIVE_GROUP_ORDER), <$f>::ZERO);
                    }
                }
            }
            proptest! {
                #[test]
                fn polynomial_roundtrip(a in any_fe()) {
                    assert_eq!(<$f>::from_polynomial_coefficients(a.to_polynomial_coefficients()), a);
                }
            }
            proptest! {
                #[test]
                fn polynomial_add(a in any_fe(), b in any_fe()) {
                    let mut poly = make_polynomial(a.to_polynomial_coefficients());
                    poly += &make_polynomial(b.to_polynomial_coefficients());
                    assert_eq!(<$f>::from_polynomial_coefficients(make_polynomial_coefficients(&poly)), a + b);
                }
            }
            proptest! {
                #[test]
                fn polynomial_mul(a in any_fe(), b in any_fe()) {
                    let mut poly = make_polynomial(a.to_polynomial_coefficients());
                    poly *= &make_polynomial(b.to_polynomial_coefficients());
                    let (_, remainder) = poly.divmod(&<$f>::reduce_multiplication_over());
                    assert_eq!(
                        <$f>::from_polynomial_coefficients(make_polynomial_coefficients(&remainder)),
                        a * b,
                    );
                }
            }

            #[test]
            fn polynomial_constants() {
                assert_eq!(
                    make_polynomial(<$f>::ZERO.to_polynomial_coefficients()),
                    Polynomial::zero()
                );
                assert_eq!(
                    make_polynomial(<$f>::ONE.to_polynomial_coefficients()),
                    Polynomial::one()
                );
            }
        }
    };
}
