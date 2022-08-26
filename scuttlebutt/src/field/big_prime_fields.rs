// This macro constructs a large (i.e., > 128 bit) prime finite field using the `ff` library.
// * $name: The name of the field.
// * $mod_name: The name of the module.
// * $modulus: The prime modulus, given as a string.
// * $generator: The mutliplicative generator, given as a string.
// * $limb: The number of `u64`s required to fit values of size `$modulus * 2` (where the `* 2`
//    requirement comes from the `ff` library).
// * $actual_limbs: The number of `u64`s required to fit values of size `$modulus`. This'll
//    generally be the same as `$limbs` except in certain edge cases where `$modulus * 2`
//    overflows `[u64; $actual_limbs]`.
// * $num_bytes: The number of bytes required to store `$modulus`, given as a `generic_array::typenum`.
// * $num_bits: The number of bits required to store `$modulus`, given as a `generic_array::typenum`.
macro_rules! big_prime_field {
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
    ) => {
        mod $mod_name {
            use crate::field::{BiggerThanModulus, FiniteField, Polynomial, PrimeFiniteField};
            use ff::{Field, PrimeField};
            use generic_array::GenericArray;
            use rand_core::{RngCore, SeedableRng};
            use std::hash::{Hash, Hasher};
            use std::ops::{AddAssign, MulAssign, SubAssign};
            use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

            $(#[$m])*
            #[derive(Debug, Eq, Clone, Copy)]
            pub struct $name {
                internal: Internal,
            }

            #[derive(PrimeField)]
            #[PrimeFieldModulus = $modulus]
            #[PrimeFieldGenerator = $generator]
            #[PrimeFieldReprEndianness = "little"]
            struct Internal([u64; $limbs]);

            impl Hash for $name {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    self.internal.0.hash(state)
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

            impl FiniteField for $name {
                type Serializer = crate::field::serialization::ByteFiniteFieldSerializer<Self>;
                type Deserializer = crate::field::serialization::ByteFiniteFieldDeserializer<Self>;

                fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
                    Self {
                        internal: Internal::random(rng),
                    }
                }

                fn inverse(&self) -> Self {
                    Self {
                        internal: self.internal.invert().unwrap(),
                    }
                }

                const ZERO: Self = Self {
                    internal: Internal::ZERO,
                };
                const ONE: Self = Self {
                    internal: Internal::ONE,
                };

                type ByteReprLen = $num_bytes;
                type FromBytesError = BiggerThanModulus;

                fn from_uniform_bytes(x: &[u8; 16]) -> Self {
                    let mut seed = [0; 32];
                    seed[0..16].copy_from_slice(x);
                    // AES key scheduling is slower than ChaCha20
                    // TODO: this is still quite slow.
                    Self::random(&mut rand_chacha::ChaCha20Rng::from_seed(seed))
                }

                fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
                    let mut bytes = [0u8; $limbs * 8];
                    bytes[0..$actual_limbs * 8].copy_from_slice(buf.as_ref());
                    $name::from_bytes_array(bytes)
                }

                /// Return the canonical byte representation (byte representation of the reduced field element).
                fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
                    let repr = self.internal.to_repr();
                    *GenericArray::from_slice(&repr.0[0..$actual_limbs * 8])
                }

                const GENERATOR: Self = Self {
                    internal: Internal::MULTIPLICATIVE_GENERATOR,
                };

                type PrimeField = Self;
                type PolynomialFormNumCoefficients = generic_array::typenum::U1;

                fn from_polynomial_coefficients(
                    coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
                ) -> Self {
                    coeff[0]
                }

                fn to_polynomial_coefficients(
                    &self,
                ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
                    GenericArray::from([*self])
                }

                fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
                    Polynomial::x()
                }

                fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
                    self * pf
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

            impl TryFrom<u128> for $name {
                type Error = BiggerThanModulus;

                fn try_from(value: u128) -> Result<Self, Self::Error> {
                    let mut bytes = [0u8; $limbs * 8];
                    let value = value.to_le_bytes();
                    bytes[0..16].copy_from_slice(&value);
                    $name::from_bytes_array(bytes)
                }
            }

            impl PrimeFiniteField for $name {}

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

            field_ops!($name);

            #[cfg(test)]
            test_field!(test_field, $name);

            #[cfg(test)]
            mod tests {
                use super::*;
                use generic_array::typenum::Unsigned;
                use num_bigint::BigUint;
                use proptest::prelude::*;

                // Test that `$num_bytes` is correct given the actual number of limbs required.
                #[test]
                fn test_num_bytes() {
                    assert_eq!(<$num_bytes as Unsigned>::U64, $actual_limbs * 8);
                }
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
                    #[test]
                    fn test_try_from(a in proptest::num::u64::ANY, b in proptest::num::u64::ANY) {
                        let a = a as u128;
                        let b = b as u128;
                        let c = a * b;
                        let aa = $name::try_from(a).unwrap();
                        let bb = $name::try_from(b).unwrap();
                        let cc = $name::try_from(c).unwrap();
                        assert_eq!(aa * bb, cc);
                    }
                }
            }

        }

        pub use $mod_name::$name;
    }
}

big_prime_field!(
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

big_prime_field!(
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
