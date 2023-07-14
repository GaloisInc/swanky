use crate::F2;
use generic_array::GenericArray;
use rand::Rng;
use std::iter::FromIterator;
use std::ops::{AddAssign, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{polynomial::Polynomial, FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{BytesDeserializationCannotFail, CanonicalSerialize};
use vectoreyes::{SimdBase, U64x2};

/// An element of the finite field $`\textsf{GF}({2^{64}})`$ reduced over $`x^{64} + x^{19} + x^{16} + x + 1`$.
#[derive(Debug, Clone, Copy, Hash, Eq)]
pub struct F64b(u64);

impl F64b {
    #[inline(always)]
    fn reduce(product: U64x2) -> Self {
        // TODO: This can almost certainly be optimized.
        let product: u128 = bytemuck::cast(product);
        let result = ((product >> 0)
            & 0b1111111111111111111111111111111111111111111111111111111111111111)
            ^ ((product >> 45)
                & 0b1111111111111111111111111111111111111111111110000000000000000000)
            ^ ((product >> 48)
                & 0b1111111111111111111111111111111111111111111111110000000000000000)
            ^ ((product >> 63)
                & 0b1111111111111111111111111111111111111111111111111111111111111110)
            ^ ((product >> 64)
                & 0b1111111111111111111111111111111111111111111111111111111111111111)
            ^ ((product >> 90) & 0b11111111111111111110000000000000000000)
            ^ ((product >> 93) & 0b00000000000000001110000000000000000)
            ^ ((product >> 96) & 0b11111111111111110000000000000000)
            ^ ((product >> 108) & 0b01111111111111111110)
            ^ ((product >> 109) & 0b1111111111111111111)
            ^ ((product >> 111) & 0b01111111111111110)
            ^ ((product >> 112) & 0b1111111111111111)
            ^ ((product >> 126) & 0b10)
            ^ ((product >> 127) & 0b1);
        Self(result as u64)
    }
}

/// Convert a [`u64`] into an [`F64b`]
///
/// This conversion treats the $`i`$-th bit of the input number as the $`i`$-th coefficient of
/// a polynomial. This polynomial form is then converted into the [`F64b`].
impl From<u64> for F64b {
    fn from(x: u64) -> Self {
        F64b(x)
    }
}

impl ConstantTimeEq for F64b {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for F64b {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u64::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a F64b> for F64b {
    #[inline]
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F64b> for F64b {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a Self) {
        // The additive inverse of GF(2^64) is the identity
        *self += rhs;
    }
}

impl<'a> MulAssign<&'a F64b> for F64b {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a Self) {
        let product = U64x2::set_lo(self.0).carryless_mul::<false, false>(U64x2::set_lo(rhs.0));
        *self = Self::reduce(product);
    }
}

impl CanonicalSerialize for F64b {
    type ByteReprLen = generic_array::typenum::U8;
    type FromBytesError = BytesDeserializationCannotFail;
    type Serializer = swanky_serialization::ByteElementSerializer<Self>;
    type Deserializer = swanky_serialization::ByteElementDeserializer<Self>;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(F64b(u64::from_le_bytes(*bytes.as_ref())))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }
}

impl FiniteRing for F64b {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Self((u128::from_le_bytes(*x) & ((1 << 64) - 1)) as u64)
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self(rng.next_u64())
    }

    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
}

impl FiniteField for F64b {
    type PrimeField = F2;

    fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
        let mut coefficients = vec![F2::ZERO; 64];
        coefficients[64 - 1] = F2::ONE;
        coefficients[19 - 1] = F2::ONE;
        coefficients[16 - 1] = F2::ONE;
        coefficients[1 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U64;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        swanky_field::standard_bit_decomposition(self.0 as u128)
    }

    const GENERATOR: Self = Self(2);

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time((1 << 64) - 2)
    }
}

swanky_field::field_ops!(F64b);

impl From<F2> for F64b {
    fn from(pf: F2) -> Self {
        Self(pf.0.into())
    }
}
impl std::ops::Mul<F64b> for F2 {
    type Output = F64b;
    #[inline]
    fn mul(self, x: F64b) -> F64b {
        // Equivalent to:
        // Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
        let new = (!((self.0 as u64).wrapping_sub(1))) & x.0;
        debug_assert!(new == 0 || new == x.0);
        F64b(new)
    }
}
impl IsSubRingOf<F64b> for F2 {}
impl IsSubFieldOf<F64b> for F2 {
    type DegreeModulo = generic_array::typenum::U64;

    fn decompose_superfield(fe: &F64b) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from_iter(
            (0..64).map(|shift| F2::try_from(((fe.0 >> shift) & 1) as u8).unwrap()),
        )
    }

    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> F64b {
        let mut out = 0;
        for x in components.iter().rev() {
            out <<= 1;
            out |= u64::from(u8::from(*x));
        }
        F64b(out)
    }
}

#[cfg(test)]
mod tests {
    use super::F64b;
    swanky_field_test::test_field!(test_field, F64b);
}
