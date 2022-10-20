#[macro_export]
macro_rules! test_associativity {
    ($name:ident, $any_element:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_element(), b in $any_element(), c in $any_element()) {
                assert_eq!(a.$op(b).$op(c), a.$op(b.$op(c)));
            }
        }
    };
}

#[macro_export]
macro_rules! test_commutativity {
    ($name:ident, $any_element:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_element(), b in $any_element()) {
                assert_eq!(a.$op(b), b.$op(a));
            }
        }
    };
}

#[macro_export]
macro_rules! test_identity {
    ($name:ident, $any_element:ident, $op:ident, $elem:expr) => {
        proptest! {
            #[test]
            fn $name(a in $any_element()) {
                assert_eq!(a.$op($elem), a);
            }
        }
    };
}

#[macro_export]
macro_rules! test_assign {
    ($name:ident, $any_element:ident, $op:ident, $assign_op:ident) => {
        proptest! {
            #[test]
            fn $name(a in $any_element(), b in $any_element()) {
                let mut out = a;
                out.$assign_op(b);
                assert_eq!(out, a.$op(b));
            }
        }
    };
}

macro_rules! test_ring {
    ($mod_name: ident, $f: ty) => {
        mod $mod_name {
            use proptest::prelude::*;
            use crate::ring::FiniteRing;
            use std::ops::{Add, Mul, Sub, AddAssign, MulAssign, SubAssign};
            fn any_element() -> impl Strategy<Value = $f> {
                any::<u128>().prop_map(|seed| <$f as $crate::field::FiniteRing>::from_uniform_bytes(&seed.to_le_bytes()))
            }

            $crate::serialization::test_serialization!(serialization, $f);

            crate::test_associativity!(additive_associativity, any_element, add);
            crate::test_associativity!(multiplicative_associativity, any_element, mul);

            crate::test_commutativity!(additive_commutativity, any_element, add);
            crate::test_commutativity!(multiplicative_commutativity, any_element, mul);

            crate::test_identity!(
                additive_identity,
                any_element,
                add,
                <$f as FiniteRing>::ZERO
            );
            crate::test_identity!(multiplicative_identity, any_element, mul, <$f>::ONE);

            crate::test_assign!(add_assign, any_element, add, add_assign);
            crate::test_assign!(sub_assign, any_element, sub, sub_assign);
            crate::test_assign!(mul_assign, any_element, mul, mul_assign);

            proptest! {
                #[test]
                fn additive_inverse(a in any_element()) {
                    let b = -a;
                    assert_eq!(a + b, <$f>::ZERO);
                }
            }

            proptest! {
                #[test]
                fn sub_and_neg(a in any_element(), b in any_element()) {
                    assert_eq!(a - b, a + (-b));
                }
            }
            proptest! {
                #[test]
                fn distributive(a in any_element(), b in any_element(), c in any_element()) {
                    assert_eq!(a * (b + c), (a * b) + (a * c));
                }
            }
            proptest! {
                #[test]
                fn sum(a in proptest::collection::vec(any_element(), proptest::collection::SizeRange::default())) {
                    let mut r = <$f>::ZERO;
                    for e in a.iter() {
                        r += *e;
                    }
                    assert_eq!(a.iter().map(|x| *x).sum::<$f>(), r);
                }
            }
            proptest! {
                #[test]
                fn true_equality_works(a in any_element()) {
                    prop_assert_eq!(a, a);
                }
            }
        }
    };
}
pub(crate) use test_ring;
