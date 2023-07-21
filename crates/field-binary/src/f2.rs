//! This module has implementations for a finite field with modulus 2.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crypto_bigint::Uint;
use generic_array::GenericArray;
use rand::Rng;
use std::{
    hash::Hash,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use swanky_field::{polynomial::Polynomial, FiniteField, FiniteRing, PrimeFiniteField};
use swanky_serialization::{BiggerThanModulus, CanonicalSerialize};
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};

/// A field element in the prime-order finite field $\textsf{GF}(2).$
#[derive(Debug, Eq, Clone, Copy, Hash, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct F2(pub(crate) u8);

const MODULUS: u8 = 2;

impl From<bool> for F2 {
    #[inline(always)]
    fn from(x: bool) -> Self {
        F2(x as u8)
    }
}
impl From<F2> for bool {
    #[inline(always)]
    fn from(x: F2) -> Self {
        x.0 != 0
    }
}

impl ConstantTimeEq for F2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for F2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F2(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl FiniteRing for F2 {
    /// This uniformly generates a field element either 0 or 1 for `F2` type.
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        // Grab the LSBit from a 32-bit integer. Rand's boolean generation doesn't do this,
        // since it's concerend about insecure random number generators.
        F2((rng.next_u32() & 1) as u8)
    }

    fn random_nonzero<R: Rng + ?Sized>(_rng: &mut R) -> Self {
        Self::ONE
    }

    const ZERO: Self = F2(0);
    const ONE: Self = F2(1);

    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        let mut value = u128::from_le_bytes(*x);
        value &= 1;
        F2(value as u8)
    }
}

impl CanonicalSerialize for F2 {
    type Serializer = F2BitSerializer;
    type Deserializer = F2BitDeserializer;
    type ByteReprLen = generic_array::typenum::U1;
    type FromBytesError = BiggerThanModulus;

    fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
        F2::try_from(u8::from_le_bytes(*buf.as_ref()))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        u8::from(*self).to_le_bytes().into()
    }
}

impl FiniteField for F2 {
    type PrimeField = Self;

    const GENERATOR: Self = F2(1);
    fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U1;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        [self.0 != 0].into()
    }

    fn inverse(&self) -> Self {
        assert_ne!(self.0, 0);
        Self::ONE
    }
}

impl AddAssign<&F2> for F2 {
    #[inline]
    fn add_assign(&mut self, rhs: &F2) {
        self.0 ^= rhs.0;
    }
}

impl SubAssign<&F2> for F2 {
    #[inline]
    fn sub_assign(&mut self, rhs: &F2) {
        self.add_assign(rhs);
    }
}

impl MulAssign<&F2> for F2 {
    #[inline]
    fn mul_assign(&mut self, rhs: &F2) {
        self.0 &= rhs.0;
    }
}

impl TryFrom<u8> for F2 {
    type Error = BiggerThanModulus;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < MODULUS {
            Ok(F2(value))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

impl TryFrom<u128> for F2 {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < MODULUS.into() {
            // This unwrap should never fail since we check that the value fits
            // in the modulus.
            Ok(F2(value.try_into().unwrap()))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

/// This returns a canonical/reduced form of the field element.
impl From<F2> for u8 {
    #[inline]
    fn from(x: F2) -> Self {
        x.0
    }
}

impl PrimeFiniteField for F2 {
    fn modulus_int<const LIMBS: usize>() -> Uint<LIMBS> {
        assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);

        // NOTE: This is OK since Uint<LIMBS> must have capacity for at least
        // one bit. The `.into()` is portable since it will cast into the
        // `crypto_bigint::Word` type, which is determined by the
        // host architecture.
        Uint::<LIMBS>::from_word(MODULUS.into())
    }

    fn into_int<const LIMBS: usize>(&self) -> Uint<LIMBS> {
        assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);

        Uint::<LIMBS>::from_u8(self.0)
    }

    fn try_from_int<const LIMBS: usize>(x: Uint<LIMBS>) -> CtOption<Self> {
        let x_eq_zero = x.ct_eq(&Uint::ZERO);
        let x_eq_one = x.ct_eq(&Uint::ONE);

        CtOption::new(
            F2::conditional_select(&F2::ZERO, &F2::ONE, x_eq_one),
            x_eq_zero | x_eq_one,
        )
    }
}

pub struct F2BitSerializer {
    current_word: u64,
    num_bits: usize,
}
impl SequenceSerializer<F2> for F2BitSerializer {
    fn serialized_size(n: usize) -> usize {
        (n / 64 + (if n % 64 == 0 { 0 } else { 1 })) * 8
    }

    fn new<W: std::io::Write>(_dst: &mut W) -> std::io::Result<Self> {
        Ok(F2BitSerializer {
            current_word: 0,
            num_bits: 0,
        })
    }

    fn write<W: std::io::Write>(&mut self, dst: &mut W, fe: F2) -> std::io::Result<()> {
        self.current_word |= (fe.0 as u64) << self.num_bits;
        self.num_bits += 1;
        if self.num_bits == 64 {
            dst.write_all(&self.current_word.to_le_bytes())?;
            self.num_bits = 0;
            self.current_word = 0;
        }
        Ok(())
    }

    fn finish<W: std::io::Write>(mut self, dst: &mut W) -> std::io::Result<()> {
        if self.num_bits > 0 {
            dst.write_all(&self.current_word.to_le_bytes())?;
            self.num_bits = 0;
        }
        Ok(())
    }
}
impl std::ops::Drop for F2BitSerializer {
    fn drop(&mut self) {
        assert_eq!(self.num_bits, 0, "F2BitSerializer.finish() not called!");
    }
}

pub struct F2BitDeserializer {
    current_word: u64,
    num_bits: usize,
}
impl SequenceDeserializer<F2> for F2BitDeserializer {
    fn new<R: std::io::Read>(_dst: &mut R) -> std::io::Result<Self> {
        Ok(F2BitDeserializer {
            current_word: 0,
            num_bits: 64,
        })
    }

    fn read<R: std::io::Read>(&mut self, src: &mut R) -> std::io::Result<F2> {
        if self.num_bits == 64 {
            self.num_bits = 0;
            let mut buf = [0; 8];
            src.read_exact(&mut buf)?;
            self.current_word = u64::from_le_bytes(buf);
        }
        let out = F2::from(self.current_word & (1 << self.num_bits) != 0);
        self.num_bits += 1;
        Ok(out)
    }
}

swanky_field::field_ops!(F2);

// TODO: these prime finite field tests should be extracted into the test utils macros.
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    impl Arbitrary for F2 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<bool>()
                .prop_map(|x| F2(if x { 1 } else { 0 }))
                .boxed()
        }
    }

    macro_rules! test_binop {
        ($name:ident, $op:ident) => {
            proptest! {
                #[test]
                fn $name(mut a in any::<F2>(), b in any::<F2>()) {
                    let mut x = a.0;
                    let y = b.0;
                    a.$op(&b);
                    // This is a hack! That's okay, this is a test!
                    if stringify!($op) == "sub_assign" {
                        x += MODULUS as u8;
                    }
                    x.$op(&y);
                    x = x % MODULUS as u8;
                    assert_eq!(a.0, x);
                }
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    swanky_field_test::test_field!(test_field, F2);
}
