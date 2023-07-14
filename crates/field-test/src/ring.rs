use proptest::strategy::Strategy;
use swanky_field::FiniteRing;

#[doc(hidden)]
#[macro_export]
macro_rules! test_associativity {
    ($name:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in any_element(), b in any_element(), c in any_element()) {
                assert_eq!(a.$op(b).$op(c), a.$op(b.$op(c)));
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! test_commutativity {
    ($name:ident, $op:ident) => {
        proptest! {
            #[test]
            fn $name(a in any_element(), b in any_element()) {
                assert_eq!(a.$op(b), b.$op(a));
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! test_identity {
    ($name:ident, $op:ident, $elem:expr) => {
        proptest! {
            #[test]
            fn $name(a in any_element()) {
                assert_eq!(a.$op($elem), a);
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! test_assign {
    ($name:ident, $op:ident, $assign_op:ident) => {
        proptest! {
            #[test]
            fn $name(a in any_element(), b in any_element()) {
                let mut out = a;
                out.$assign_op(b);
                assert_eq!(out, a.$op(b));
            }
        }
    };
}

/// A proptest [`Strategy`] to generate a random finite ring.
pub fn arbitrary_ring<R: FiniteRing>() -> impl Strategy<Value = R> {
    proptest::prelude::any::<u128>().prop_map(|seed| R::from_uniform_bytes(&seed.to_le_bytes()))
}

/// Test that an implementation follows the finite ring axioms.
///
/// Run it like `swanky_field_test::test_ring!(ring_tests, MyFunRing)` where `ring_tests` is an
/// arbitrary module name used to namespace the tests, and `MyFunRing` is the ring to test.
#[macro_export]
macro_rules! test_ring {
    ($mod_name: ident, $ring: ty) => {
        mod $mod_name {
            use super::*;
            type R = $ring;
            // We make tests a separate module, so that we can avoid the `use super::*;` from
            // polluting the tests namespace. We need the `use super::*;` above, because `$f` might
            // be an unqualified name in the super namespace.
            mod tests {
                use super::R;
                use $crate::__internal_macro_exports::*;
                use swanky_field::FiniteRing;
                use swanky_serialization::CanonicalSerialize;
                use proptest::prelude::*;
                use std::ops::{Add, Mul, Sub, AddAssign, MulAssign, SubAssign};
                fn any_element() -> impl Strategy<Value = R> {
                    $crate::arbitrary_ring::<R>()
                }

                proptest! {
                    #[test]
                    fn to_and_from_bytes(a in any_element()) {
                        let buf = a.to_bytes();
                        assert_eq!(a, R::from_bytes(&buf).unwrap());
                    }
                }
                proptest! {
                    #[test]
                    fn canonical_serialization_is_canonical(a in any_element(), b in any_element()) {
                        if a == b {
                            prop_assert_eq!(a.to_bytes(), b.to_bytes());
                        } else {
                            prop_assert_ne!(a.to_bytes(), b.to_bytes());
                        }
                    }
                }

                $crate::test_associativity!(additive_associativity, add);
                $crate::test_associativity!(multiplicative_associativity, mul);

                $crate::test_commutativity!(additive_commutativity, add);
                $crate::test_commutativity!(multiplicative_commutativity, mul);

                $crate::test_identity!(
                    additive_identity,
                    add,
                    <R as FiniteRing>::ZERO
                );
                $crate::test_identity!(multiplicative_identity, mul, R::ONE);

                $crate::test_assign!(add_assign, add, add_assign);
                $crate::test_assign!(sub_assign, sub, sub_assign);
                $crate::test_assign!(mul_assign, mul, mul_assign);

                proptest! {
                    #[test]
                    fn additive_inverse(a in any_element()) {
                        let b = -a;
                        assert_eq!(a + b, R::ZERO);
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
                        let mut r = R::ZERO;
                        for e in a.iter() {
                            r += *e;
                        }
                        assert_eq!(a.iter().map(|x| *x).sum::<R>(), r);
                    }
                }
                proptest! {
                    #[test]
                    fn true_equality_works(a in any_element()) {
                        prop_assert_eq!(a, a);
                    }
                }
            }
        }
    };
}
