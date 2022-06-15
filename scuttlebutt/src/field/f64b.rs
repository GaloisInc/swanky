use crate::field::{
    polynomial::Polynomial, BytesDeserializationCannotFail, FiniteField, IsSubfieldOf, F2,
};
use generic_array::GenericArray;
use rand_core::RngCore;
use smallvec::smallvec;
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::ops::{AddAssign, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
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

impl FiniteField for F64b {
    type ByteReprLen = generic_array::typenum::U8;
    type FromBytesError = BytesDeserializationCannotFail;
    type Serializer = crate::field::serialization::ByteFiniteFieldSerializer<Self>;
    type Deserializer = crate::field::serialization::ByteFiniteFieldDeserializer<Self>;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(F64b(u64::from_le_bytes(*bytes.as_ref())))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }

    type PrimeField = F2;
    type PolynomialFormNumCoefficients = generic_array::typenum::U64;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        let mut out = 0;
        for x in coeff.iter().rev() {
            out <<= 1;
            out |= u64::from(u8::from(*x));
        }
        Self(out)
    }

    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Self((u128::from_le_bytes(*x) & ((1 << 64) - 1)) as u64)
    }

    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        let x = self.0;
        GenericArray::from_iter(
            (0..64).map(|shift| F2::try_from(((x >> shift) & 1) as u8).unwrap()),
        )
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        let mut coefficients = smallvec![F2::ZERO; 64];
        coefficients[64 - 1] = F2::ONE;
        coefficients[19 - 1] = F2::ONE;
        coefficients[16 - 1] = F2::ONE;
        coefficients[1 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }

    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        Self(rng.next_u64())
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U64;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        super::standard_bit_decomposition(self.0 as u128)
    }

    const GENERATOR: Self = Self(2);
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
    }

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow((1 << 64) - 2)
    }
}

impl IsSubfieldOf<F64b> for F2 {
    fn multiply_by_superfield(&self, x: F64b) -> F64b {
        x.multiply_by_prime_subfield(*self)
    }

    fn lift_into_superfield(&self) -> F64b {
        F64b(self.0 as u64)
    }
}

field_ops!(F64b);

#[cfg(test)]
test_field!(test_gf64, F64b);
