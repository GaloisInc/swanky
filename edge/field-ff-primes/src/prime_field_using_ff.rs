/// If a field only contains one limb, we can do random number generation more
/// efficiently than done in `ff` (by roughly 2x) by using `Uniform::from`.
/// That's what this macro does: If no arguments are passed we use `ff`s `random`
/// method, and if a modulus is passed we use `Uniform::from` instead.
macro_rules! random_function_helper {
    () => {
        fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
            Self {
                internal: Internal::random(rng),
            }
        }
    };

    ($modulus: expr) => {
        fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
            use rand::distr::{Distribution, Uniform};
            Self {
                internal: internal::new_internal([Uniform::try_from(0..$modulus)
                    .expect("bounds finite and low < high")
                    .sample(rng)]),
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
                // // TODO: Super patchy work, works for now, make it elegant
                // // NOTE: Chnaces of something getting "falsely encoded" due to the if statements is low ':),, but still fix this patchy fix
                // // For the              F256p                                       F384p                                           F400p
                // if value == 0xffffffffffffffffffffffffffffff43
                //     || value == 0xfffffffffffffffffffffffffffffec3
                //     || value == 0xfffffffffffffffffffffffffffffdaf
                // {
                //     let mut bytes = [0u8; $limbs * 8];
                //     let val_lo = value.to_le_bytes();
                //     let val_hi = (0xffffffffffffffffffffffffffffffff as u128).to_le_bytes();
                //     bytes[0..16].copy_from_slice(&val_lo);
                //     bytes[16..32].copy_from_slice(&val_hi);
                //     $name::from_bytes_array(bytes)
                // } else {
                    let mut bytes = [0u8; $limbs * 8];
                    let value = value.to_le_bytes();
                    bytes[0..16].copy_from_slice(&value);
                    $name::from_bytes_array(bytes)
                // }
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
use swanky_field_fft::FieldForFFT;
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
            use swanky_field::{FiniteField, PrimeFiniteField, FiniteRing};
            use swanky_serialization::{CanonicalSerialize};
            use swanky_field::{BiggerThanModulus};
            use ff::{Field, PrimeField};
            use generic_array::{typenum::Unsigned, GenericArray};
            use rand_core::{Rng, SeedableRng};
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

                fn as_int<const LIMBS: usize>(&self) -> Uint<LIMBS> {
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
            swanky_field_test::test_field!(test_field, $name, Polynomial::x);

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

// NOTE: Primes just less than a power of two
// https://t5k.org/lists/2small/0bit.html
prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{32} - 527`$.
    F32p,
    f32p,
    modulus = "4294966769",
    generator = "3",
    limbs = 1,
    actual_limbs = 1,
    num_bytes = generic_array::typenum::U4,
    num_bits = generic_array::typenum::U32,
    single_limb_modulus = 4294966769
);
impl FieldForFFT<2> for F32p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([1u128, 4294966768u128][ix]).unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{61} - 1`$.
    F61p,
    f61p,
    modulus = "2305843009213693951",
    generator = "37",
    limbs = 1,
    actual_limbs = 1,
    num_bytes = generic_array::typenum::U8,
    num_bits = generic_array::typenum::U61,
    single_limb_modulus = 2305843009213693951
);
impl FieldForFFT<2> for F61p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([1u128, 2305843009213693950u128][ix]).unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{61} - 1`$.
    F64p,
    f64p,
    modulus = "18446744073709551521",
    generator = "3",
    limbs = 2,
    actual_limbs = 2,
    num_bytes = generic_array::typenum::U8,
    num_bits = generic_array::typenum::U64,
);
impl FieldForFFT<2> for F64p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([1u128, 18446744073709551520u128][ix]).unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{127} - 511`$.
    F127p,
    f127p,
    modulus = "170141183460469231731687303715884105727",
    generator = "43",
    limbs = 2,
    actual_limbs = 2,
    num_bytes = generic_array::typenum::U16,
    num_bits = generic_array::typenum::U127,
);
impl FieldForFFT<2> for F127p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([1u128, 170141183460469231731687303715884105726u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{127} - 511`$.
    Frs127p,
    frs127rsp,
    modulus = "170141183460469231731687303715884105217",
    generator = "5",
    limbs = 2,
    actual_limbs = 2,
    num_bytes = generic_array::typenum::U16,
    num_bits = generic_array::typenum::U127,
);
impl FieldForFFT<2> for Frs127p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([1u128, 170141183460469231731687303715884105216u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// The finite field over the prime
    /// $`P = 2^{128} - 159`$.
    F128p,
    f128p,
    modulus = "340282366920938463463374607431768211297",        // This mod is fine!!
    generator = "5",
    limbs = 3,
    actual_limbs = 2,
    num_bytes = generic_array::typenum::U16,
    num_bits = generic_array::typenum::U128,
);
impl FieldForFFT<2> for F128p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from(
            [
                1u128,
                340282366920938463463374607431768211296u128,
                104721963583583438841328038195075850306u128,
            ][ix],
        )
        .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// NOTE: Previous prime in the field-ff-primes crate
    /// The finite field over the prime
    /// $`P = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1
    ///     = 115792089210356248762697446949407573530086143415290314195533631308867097853951`$.
    /// NOTE: New minus small n prime
    /// /// $`P = 2^{256} - 189`$.
    F256p,
    f256p,
    //modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951",   // OLD
    // modulus = "115792089237316195423570985008687907853269984665640564039457584007913129639747",     // NEW
    modulus = "115792089237316195423570985008687907853269984665640564039457584007913129637873",     // EVEN NEWER
    generator = "3",
    limbs = 5,
    actual_limbs = 4,
    num_bytes = generic_array::typenum::U32,
    num_bits = generic_array::typenum::U256,
);
impl FieldForFFT<2> for F256p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffffffffffff740 as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// NOTE: Previous prime in the field-ff-primes crate
    /// The finite field over the prime
    /// $`P = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1
    ///     = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319`$.
    /// NOTE: New minus small n prime
    /// $`P = 2^{384} - 317
    F384p,
    f384p,
    // modulus = "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",    // OLD
    modulus = "39402006196394479212279040100143613805079739270465446667948293404245721771497210611414266254884915640806627990306499",       // NEW
    generator = "19",
    limbs = 7,
    actual_limbs = 6,
    num_bytes = generic_array::typenum::U48,
    num_bits = generic_array::typenum::U384,
);
impl FieldForFFT<2> for F384p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffffffffffffec3 as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

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
impl FieldForFFT<2> for F400p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffffffffffffdaf as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

// These primes are not 2^n - small number, but rather p = c*2^32 + 1
prime_field_using_ff!(
    /// NTT friendly 512 bit prime
    Frs512p,
    frs512p,
    modulus = "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433644711116801",
    generator = "2653135687665933732116392076509140650815216084673071913799274672109843317862972825520025532916796169010684541040936963921422520982516932732201540090815717",
    limbs = 9,
    actual_limbs = 8,
    num_bytes = generic_array::typenum::U64,
    num_bits = generic_array::typenum::U512,
);
impl FieldForFFT<2> for Frs512p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffffffff0000000 as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// NTT friendly 1024 bit prime
    Frs1024p,
    frs1024p,
    modulus = "179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356321244742942721",
    generator = "22832505786862897753078148751680270733331860838970131534296869387398223592305000977443419498510768487946698509029933304554893106469031756257836068742741753857530940829270365898820714812107283520410028918716711472464971819042262220977649135314963906236952025626572871773751662397013380098453055619232777035002",
    limbs = 17,
    actual_limbs = 16,
    num_bytes = generic_array::typenum::U128,
    num_bits = generic_array::typenum::U1024,
);
impl FieldForFFT<2> for Frs1024p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffff86100000000 as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}

prime_field_using_ff!(
    /// NTT friendly 2048 bit prime
    Frs2048p,
    frs2048p,
    modulus = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853608091773829121",
    generator = "19291268532031067759301150772075288269172959059986750385164537061588752247453891949112826850975506531846971683485645819908013063087583765064790667687829608302309585343733315555577226135707678370442081781594564425075189427722345213073755396389829538731742120536104661349993511406620515573999970364358896506283192130919939719398055592064934576695989980001196194447336815253162667681945826745986282495032064633858026988864668286535558680800954268566664168613432327544436290907225483521470116696952512531713709956495386762365556231280187748786807690833120859284395608997017327545790909648604065027828113847539067671506549",
    limbs = 33,
    actual_limbs = 32,
    num_bytes = generic_array::typenum::U256,
    num_bits = generic_array::typenum::U2048,
);
impl FieldForFFT<2> for Frs2048p {
    const PHI_EXP: usize = 1;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from([0xfffffffffffffffffffffd4d00000000 as u128][ix])
            .unwrap_or_else(|_| unreachable!())
    }
}


// prime_field_using_ff!(
//     /// NTT friendly 4096 bit prime
//     Frs4096p,
//     frs4096p,
//     modulus = "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708331937773649921",
//     generator = "661116002378496070632204327520180531229884591342196550548728348889932751513724944289698237713067706900813400836486358120970071286369123762317908198637968901859354324473589772911113983639371232203073419464672446484894198554307456766828137741037269923904965016789857059962326474481647230145761407243484721427921901466576848867678175563658924958764838117424367532286051199313584659556944423726297836513993700081117357168913889220894117310060266478025302873023864246518692907657216419375206424142417591747130142394410009344625233502303177686612333995227661716648914007090627187341157314111492489467797704579803028627274577884005217158222805268126417263893361413343450683133936654549033155202827771294074265309529727921391440704623788872807590064457780722052446280938651128594824953284322877989028248677636084908666601869460996215497303487251768679344620313765979580045688474312838302932543396108015321341548551896991661643980441497396170051035904644095337944826640012010731134572739883143530321055330201225938961206973055436326262752855360358670516267215178406784094165408355782861184429335186889669416783409991871612140613212789103635489545298470228856091259361931581505889732818111318949591638381451748695740321093481346352371765519550",
//     limbs = 65,
//     actual_limbs = 64,
//     num_bytes = generic_array::typenum::U512,
//     num_bits = generic_array::typenum::U4096,
// );
// impl FieldForFFT<2> for Frs4096p {
//     const PHI_EXP: usize = 1;

//     #[inline]
//     fn roots(ix: usize) -> Self {
//         Self::try_from([0xfffffffffffffffffffff84d00000000 as u128][ix])
//             .unwrap_or_else(|_| unreachable!())
//     }
// }