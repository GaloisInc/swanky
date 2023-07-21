/// If a field only contains one limb, we can do random number generation more
/// efficiently than done in `ff` (by roughly 2x) by using `Uniform::from`.
/// That's what this macro does: If no arguments are passed we use `ff`s `random`
/// method, and if a modulus is passed we use `Uniform::from` instead.
macro_rules! random_function_helper {
    () => {
        fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
            Self {
                internal: Internal::random(rng),
            }
        }
    };

    ($modulus: expr) => {
        fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
            use rand::distributions::{Distribution, Uniform};
            Self {
                internal: internal::new_internal([Uniform::from(0..$modulus).sample(rng)]),
            }
        }
    };
}
pub(crate) use random_function_helper;

/// Helper macro for `TryFrom<u128>` which is needed if there's only one limb.
macro_rules! try_from_helper {
    ($name: ident, $limbs: expr,) => {
        impl TryFrom<u128> for $name {
            type Error = BiggerThanModulus;

            fn try_from(value: u128) -> Result<Self, Self::Error> {
                let mut bytes = [0u8; $limbs * 8];
                let value = value.to_le_bytes();
                bytes[0..16].copy_from_slice(&value);
                $name::from_bytes_array(bytes)
            }
        }
    };
    ($name: ident, $limbs: expr, $single_limb_modulus: expr) => {
        impl TryFrom<u128> for $name {
            type Error = BiggerThanModulus;

            fn try_from(value: u128) -> Result<Self, Self::Error> {
                if value > u64::MAX as u128 {
                    // No values larger than a `u64` will work if there's
                    // only one limb.
                    return Err(BiggerThanModulus);
                }
                let mut bytes = [0u8; $limbs * 8];
                // Because we check above that `value` fits in a `u64`, the
                // below cast should be okay.
                let value = (value as u64).to_le_bytes();
                bytes[0..8].copy_from_slice(&value);
                $name::from_bytes_array(bytes)
            }
        }
    };
}
pub(crate) use try_from_helper;

/// This macro constructs a prime finite field using the `ff` library.
/// The modulus and generator should be listed, along with the name, in `build.rs`.
/// * `$name`: The name of the field.
/// * `$mod_name`: The name of the module containing the field.
/// * `$modulus`: The prime modulus, given as a string.
/// * `$generator`: The multiplicative generator, given as a string.
/// * `$limbs`: The number of `u64`s required to fit values of size `$modulus * 2` (where the `* 2`
///    requirement comes from the `ff` library).
/// * `$actual_limbs`: The number of `u64`s required to fit values of size `$modulus`. This'll
///    generally be the same as `$limbs` except in certain edge cases where `$modulus * 2`
///    overflows `[u64; $actual_limbs]`.
/// * `$num_bytes`: The number of bytes required to store `$modulus`, given as a `generic_array::typenum`.
/// * `$num_bits`: The number of bits required to store `$modulus`, given as a `generic_array::typenum`.
/// * \[Optional\] `$single_limb_modulus`: If `$limbs` is one, then this can contain `$modulus`
///    (given as an _integer_ not a string!) to enable faster random value generation.
macro_rules! prime_field_using_ff {
    (
        $(#[$m: meta])*
        $name: ident,
        $mod_name: ident,
        modulus = $modulus: expr,
        generator = $generator: expr,
        limbs = $limbs: expr,
        actual_limbs = $actual_limbs: expr,
        num_bytes = $num_bytes: ty,
        num_bits = $num_bits: ty,
        $(single_limb_modulus = $single_limb_modulus: expr)?
    ) => {
        mod $mod_name {
            use swanky_field::{FiniteField, polynomial::Polynomial, PrimeFiniteField, FiniteRing};
            use swanky_serialization::{CanonicalSerialize, BiggerThanModulus};
            use ff::{Field, PrimeField};
            use generic_array::{typenum::Unsigned, GenericArray};
            use rand_core::{RngCore, SeedableRng};
            use std::hash::{Hash, Hasher};
            use std::ops::{AddAssign, MulAssign, SubAssign};
            use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption};
            use crypto_bigint::Uint;

            #[allow(non_camel_case_types, unused_variables, unused_mut, dead_code)]
            mod internal {
                include!(concat!(env!("OUT_DIR"), "/ff-", stringify!($name) , ".rs"));
                #[test]
                fn build_file_matches_macro() {
                    assert_eq!(MODULUS_STRING, $modulus);
                    assert_eq!(GENERATOR_STRING, $generator);
                    assert_eq!(std::mem::size_of::<Internal>() / std::mem::size_of::<u64>(), $limbs);
                    assert_eq!(std::mem::size_of::<Internal>() % std::mem::size_of::<u64>(), 0);
                }
                #[inline]
                pub(super) fn get_internal(internal: &Internal) -> &[u64; $limbs] {
                    &internal.0
                }
                #[inline]
                pub(super) fn new_internal(x: [u64; $limbs]) -> Internal {
                    Internal(x)
                }
            }
            use internal::{Internal, InternalRepr, get_internal};

            $(#[$m])*
            #[derive(Debug, Eq, Clone, Copy)]
            pub struct $name {
                internal: Internal,
            }

            impl Hash for $name {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    get_internal(&self.internal).hash(state)
                }
            }

            impl ConstantTimeEq for $name {
                fn ct_eq(&self, other: &Self) -> Choice {
                    self.internal.ct_eq(&other.internal)
                }
            }
            impl ConditionallySelectable for $name {
                fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                    Self {
                        internal: Internal::conditional_select(&a.internal, &b.internal, choice),
                    }
                }
            }

            impl $name {
                fn from_bytes_array(bytes: [u8; $limbs * 8]) -> Result<Self, BiggerThanModulus> {
                    // XXX: Is `_vartime` okay here?
                    let out = Internal::from_repr_vartime(InternalRepr(bytes));
                    if let Some(out) = out {
                        Ok(Self { internal: out })
                    } else {
                        Err(BiggerThanModulus)
                    }
                }
            }

            impl CanonicalSerialize for $name {
                type Serializer = swanky_serialization::ByteElementSerializer<Self>;
                type Deserializer = swanky_serialization::ByteElementDeserializer<Self>;

                type ByteReprLen = $num_bytes;
                type FromBytesError = BiggerThanModulus;

                fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
                    let mut bytes = [0u8; $limbs * 8];
                    bytes[..Self::ByteReprLen::USIZE].copy_from_slice(buf.as_ref());
                    $name::from_bytes_array(bytes)
                }

                /// Return the canonical byte representation (byte representation of the reduced field element).
                fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
                    let repr = self.internal.to_repr();
                    *GenericArray::from_slice(&repr.0[..Self::ByteReprLen::USIZE])
                }
            }

            impl FiniteRing for $name {
                $crate::prime_field_using_ff::random_function_helper!($($single_limb_modulus)?);

                const ZERO: Self = Self {
                    internal: Internal::ZERO,
                };
                const ONE: Self = Self {
                    internal: Internal::ONE,
                };

                fn from_uniform_bytes(x: &[u8; 16]) -> Self {
                    let mut seed = [0; 32];
                    seed[0..16].copy_from_slice(x);
                    // AES key scheduling is slower than ChaCha20
                    // TODO: this is still quite slow.
                    Self::random(&mut rand_chacha::ChaCha20Rng::from_seed(seed))
                }
            }

            impl FiniteField for $name {
                fn inverse(&self) -> Self {
                    Self {
                        internal: self.internal.invert().unwrap(),
                    }
                }

                const GENERATOR: Self = Self {
                    internal: Internal::MULTIPLICATIVE_GENERATOR,
                };

                type PrimeField = Self;

                fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
                    Polynomial::x()
                }

                type NumberOfBitsInBitDecomposition = $num_bits;

                fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
                    let mut out: GenericArray<bool, Self::NumberOfBitsInBitDecomposition> = Default::default();
                    let bytes = self.to_bytes();
                    for (i, dst) in out.iter_mut().enumerate() {
                        let bits = bytes[i / 8];
                        *dst = (bits & (1 << ((i % 8) as u8))) != 0;
                    }
                    out
                }
            }

            crate::try_from_helper!($name, $limbs, $($single_limb_modulus)?);

            impl PrimeFiniteField for $name {
                fn modulus_int<const LIMBS: usize>() -> Uint<LIMBS> {
                    assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);

                    let mut limbs = [0; LIMBS];

                    // NOTE: Depends on little-endianness!
                    bytemuck::bytes_of_mut(&mut limbs)[..Self::ByteReprLen::USIZE]
                        .copy_from_slice(internal::MODULUS_BYTES);

                    Uint::from_words(limbs)
                }

                fn into_int<const LIMBS: usize>(&self) -> Uint<LIMBS> {
                    assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);

                    let mut limbs = [0; LIMBS];

                    // NOTE: Depends on little-endianness (and
                    // `CanonicalSerialize`, which is OK since we wrote it.)
                    bytemuck::bytes_of_mut(&mut limbs)[..Self::ByteReprLen::USIZE]
                        .copy_from_slice(&self.to_bytes());

                    Uint::from_words(limbs)
                }

                fn try_from_int<const LIMBS: usize>(x: Uint<LIMBS>) -> CtOption<Self> {
                    let x_lt_modulus = x.ct_lt(&Self::modulus_int());

                    CtOption::new(
                        // NOTE: Depends on little-endianness (and
                        // `CanonicalSerialize`, which is OK since we wrote
                        // it.) Furthermore, this will not panic, since if
                        // x >= Self::modulus_int(), there are _at least_
                        // Self::ByteReprLen bytes, and we will simply read the
                        // first Self::ByteReprLen (and not do anything with
                        // them due to the modulus Choice.)
                        Self::from_bytes(
                            &GenericArray::from_slice(
                                &bytemuck::bytes_of(x.as_words())[..Self::ByteReprLen::USIZE]
                            )
                        )
                        .unwrap(),
                        x_lt_modulus,
                    )
                }
            }

            impl AddAssign<&$name> for $name {
                fn add_assign(&mut self, rhs: &$name) {
                    self.internal.add_assign(rhs.internal);
                }
            }

            impl SubAssign<&$name> for $name {
                fn sub_assign(&mut self, rhs: &$name) {
                    self.internal.sub_assign(rhs.internal);
                }
            }

            impl MulAssign<&$name> for $name {
                fn mul_assign(&mut self, rhs: &$name) {
                    self.internal.mul_assign(rhs.internal);
                }
            }

            swanky_field::field_ops!($name);

            #[cfg(test)]
            swanky_field_test::test_field!(test_field, $name);

            #[cfg(test)]
            mod tests {
                use super::*;
                use generic_array::typenum::Unsigned;
                use num_bigint::BigUint;
                use proptest::prelude::*;

                // Test that `$num_bits` is correct given the modulus.
                #[test]
                fn test_num_bits() {
                    let modulus: BigUint = $modulus.parse().unwrap();
                    assert_eq!(<$num_bits as Unsigned>::U64, modulus.bits());
                }
                // Test that `$limbs` is correct given the modulus.
                #[test]
                fn test_limbs() {
                    let modulus: BigUint = $modulus.parse().unwrap();
                    let modulus_times_two: BigUint = modulus * 2u64;
                    assert_eq!($limbs, (modulus_times_two.bits() as f64 / 64f64).ceil() as u64);
                }
                // Test that `$actual_limbs` is correct given the modulus.
                #[test]
                fn test_actual_limbs() {
                    let modulus: BigUint = $modulus.parse().unwrap();
                    assert_eq!($actual_limbs, (modulus.bits() as f64 / 64f64).ceil() as u64);
                }
                // Test that the `TryFrom` implementation is correct.
                proptest! {
                    // Since `ff` fields can be as small as a single `u64`, we generate `u32`s.
                    #[test]
                    fn test_try_from(a in proptest::num::u32::ANY, b in proptest::num::u32::ANY) {
                        let a = a as u128;
                        let b = b as u128;
                        let c = a * b;
                        let aa = $name::try_from(a).unwrap();
                        let bb = $name::try_from(b).unwrap();
                        match $name::try_from(c) {
                            Ok(cc) => assert_eq!(aa * bb, cc),
                            Err(_) => (),
                        }
                    }
                }
                // Test that `$modulus` and `$single_limb_modulus` are the same.
                $(
                #[test]
                fn test_single_limb_modulus() {
                    let modulus: u64 = $modulus.parse().unwrap();
                    assert_eq!(modulus, $single_limb_modulus);
                })?
            }

        }

        pub use $mod_name::$name;
    }
}
pub(crate) use prime_field_using_ff;

// The modulus and generator for these fields is specified in `build.rs`
prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1
    ///     = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319`$.
    F384p,
    f384p,
    modulus = "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
    generator = "19",
    limbs = 7,
    actual_limbs = 6,
    num_bytes = generic_array::typenum::U48,
    num_bits = generic_array::typenum::U384,
);

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`Q = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643`$.
    F384q,
    f384q,
    modulus = "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643",
    generator = "19",
    limbs = 7,
    actual_limbs = 6,
    num_bytes = generic_array::typenum::U48,
    num_bits = generic_array::typenum::U384,
);

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{128} - 159`$.
    F128p,
    f128p,
    modulus = "340282366920938463463374607431768211297",
    generator = "5",
    limbs = 3,
    actual_limbs = 2,
    num_bytes = generic_array::typenum::U16,
    num_bits = generic_array::typenum::U128,
);

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1
    ///     = 115792089210356248762697446949407573530086143415290314195533631308867097853951`$.
    F256p,
    f256p,
    modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    generator = "6",
    limbs = 5,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U256,
);

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{256} - 2^{32} - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    ///     = 115792089237316195423570985008687907853269984665640564039457584007908834671663`$.
    /// This field is used in the secp256k1 curve.
    Secp256k1,
    secp256k1,
    modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    generator = "3",
    limbs = 5,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U256,
);

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 115792089237316195423570985008687907852837564279074904382605163141518161494337`$.
    /// This prime is the order of the secp256k1 curve.
    Secp256k1order,
    secp256k1order,
    modulus = "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    generator = "7",
    limbs = 5,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U256,
);

prime_field_using_ff!(
    /// The BLS12-381 finite field.
    Fbls12381,
    fbls12381,
    modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513",
    generator = "7",
    limbs = 4,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U255,
);

prime_field_using_ff!(
    /// The BN-254 finite field.
    Fbn254,
    fbn254,
    modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    generator = "5",
    limbs = 4,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U254,
);

prime_field_using_ff!(
    /// The finite field over the prime $`2^{400} - 593`$.
    F400p,
    f400p,
    modulus = "2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747492783",
    generator = "5",
    limbs = 7,
    actual_limbs = 7,
    num_bytes = generic_array::typenum::U50,
    num_bits = generic_array::typenum::U400,
);
