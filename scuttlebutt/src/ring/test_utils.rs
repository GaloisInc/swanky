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

#[macro_export]
macro_rules! test_serialization {
    ($mod_name: ident, $f: ty) => {
        mod $mod_name {
            use proptest::prelude::*;
            use crate::serialization::CanonicalSerialize;
            fn any_element() -> impl Strategy<Value=$f> {
                any::<u128>().prop_map(|seed| {
                    <$f as $crate::field::FiniteRing>::from_uniform_bytes(&seed.to_le_bytes())
                })
            }
            proptest! {
                #[test]
                fn to_and_from_bytes(a in any_element()) {
                    let buf = a.to_bytes();
                    assert_eq!(a, <$f>::from_bytes(&buf).unwrap());
                }
            }
            proptest! {
                #[test]
                fn false_equality_works(a in any_element(), b in any_element()) {
                    if a == b {
                        prop_assert_eq!(a.to_bytes(), b.to_bytes());
                    } else {
                        prop_assert_ne!(a.to_bytes(), b.to_bytes());
                    }
                }
            }
            proptest! {
                #[test]
                fn serde_serialize_serde_json(a in any_element()) {
                    let ser = serde_json::to_string(&a).unwrap();
                    let b: $f = serde_json::from_str(&ser).unwrap();
                    assert_eq!(a, b);
                }
            }
            proptest! {
                #[test]
                fn serde_serialize_bincode(a in any_element()) {
                    let ser = bincode::serialize(&a).unwrap();
                    let b: $f = bincode::deserialize(&ser).unwrap();
                    assert_eq!(a, b);
                }
            }
            proptest! {
                #[test]
                fn serialize(xs in proptest::collection::vec(any_element(), proptest::collection::SizeRange::default())) {
                    use crate::serialization::*;
                    let mut buf = Vec::new();
                    let mut cursor = std::io::Cursor::new(&mut buf);
                    let mut serializer = <$f as CanonicalSerialize>::Serializer::new(&mut cursor).unwrap();
                    for x in xs.iter().copied() {
                        serializer.write(&mut cursor, x).unwrap();
                    }
                    serializer.finish(&mut cursor).unwrap();
                    prop_assert_eq!(cursor.get_ref().len(), <$f as CanonicalSerialize>::Serializer::serialized_size(xs.len()));
                    cursor.set_position(0);
                    let mut deserializer = <$f as CanonicalSerialize>::Deserializer::new(&mut cursor).unwrap();
                    for x in xs.into_iter() {
                        prop_assert_eq!(x, deserializer.read(&mut cursor).unwrap());
                    }
                }
            }
            #[cfg(feature = "serde")]
            proptest! {
                #[test]
                fn serde_serialize_vec(xs in proptest::collection::vec(any_element(), proptest::collection::SizeRange::default())) {
                    use crate::serialization::serde_vec;
                    #[derive(serde::Serialize, serde::Deserialize)]
                    struct Struct {
                        #[serde(with = "serde_vec")]
                        v: Vec<$f>
                    }
                    let xs = Struct {v: xs};
                    let bytes = bincode::serialize(&xs).unwrap();
                    let ys: Struct = bincode::deserialize(&bytes).unwrap();
                    for (x, y) in xs.v.into_iter().zip(ys.v.into_iter()) {
                        prop_assert_eq!(x, y);
                    }
                }
            }
        }
    }
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

            crate::test_serialization!(serialization, $f);

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
