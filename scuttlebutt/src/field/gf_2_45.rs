use crate::field::{f2::F2, polynomial::Polynomial, FiniteField, IsSubfieldOf};
use generic_array::GenericArray;
use rand_core::RngCore;
use smallvec::smallvec;
use std::{
    convert::TryFrom,
    iter::FromIterator,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use vectoreyes::{SimdBase, U64x2};

/// An element of the finite field $\textsf{GF}(2^{45})$ reduced over $x^{45} + x^{28} + x^{17} + x^{11} + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
pub struct Gf45(pub(crate) u64);

impl ConstantTimeEq for Gf45 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for Gf45 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf45(u64::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a Gf45> for Gf45 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a Gf45) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a Gf45> for Gf45 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a Gf45) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}

impl<'a> MulAssign<&'a Gf45> for Gf45 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a Gf45) {
        let wide_product: u128 = {
            let product = U64x2::set_lo(self.0).carryless_mul::<false, false>(U64x2::set_lo(rhs.0));
            bytemuck::cast(product)
        };
        // Now we reduce the wide product.
        self.0 = ((wide_product >> 0)
            & 0b0000000000000000000111111111111111111111111111111111111111111111
            ^ (wide_product >> 17)
                & 0b0000000000000000000111111111111111110000000000000000000000000000
            ^ (wide_product >> 28)
                & 0b0000000000000000000111111111111111111111111111100000000000000000
            ^ (wide_product >> 34) & 0b0000000000000000000000000000001111111111111111100000000000
            ^ (wide_product >> 45) & 0b00111111111111111110000000000011111111111111111
            ^ (wide_product >> 51) & 0b11111111111111111111111111111100000000000
            ^ (wide_product >> 56) & 0b111111111111111111100000000000000000
            ^ (wide_product >> 62) & 0b110000000000000000011111111111
            ^ (wide_product >> 73) & 0b0011111111111111111
            ^ (wide_product >> 79) & 0b1100000000000
            ^ (wide_product >> 90) & 0b11) as u64;
    }
}

/// The serialized form of the GF(2^45) value is bigger than its modulus.
#[derive(Clone, Copy, Debug)]
pub struct Gf45ValueBiggerThanModulus;
impl std::fmt::Display for Gf45ValueBiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "The serialized form of the GF(2^45) value is bigger than its modulus."
        )
    }
}
impl std::error::Error for Gf45ValueBiggerThanModulus {}

impl FiniteField for Gf45 {
    type ByteReprLen = generic_array::typenum::U6;
    type FromBytesError = Gf45ValueBiggerThanModulus;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        let mut buf = [0; 8];
        &mut buf[0..6].copy_from_slice(bytes);
        let raw = u64::from_le_bytes(buf);
        if raw < (1 << 45) {
            Ok(Gf45(raw))
        } else {
            Err(Gf45ValueBiggerThanModulus)
        }
    }

    #[inline]
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        GenericArray::from_slice(&self.0.to_le_bytes()[0..6]).clone()
    }

    type PrimeField = F2;
    type PolynomialFormNumCoefficients = generic_array::typenum::U45;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        let mut out = 0;
        for x in coeff.iter().rev() {
            out <<= 1;
            out |= u64::from(u8::from(*x));
        }
        Gf45(out)
    }

    #[inline]
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Gf45((u128::from_le_bytes(*x) & ((1 << 45) - 1)) as u64)
    }

    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        let x = self.0;
        GenericArray::from_iter(
            (0..45).map(|shift| F2::try_from(((x >> shift) & 1) as u8).unwrap()),
        )
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        //X2^45 + X2^28 + X2^17 + X2^11 + 1
        let mut coefficients = smallvec![F2::ZERO; 128];
        coefficients[45 - 1] = F2::ONE;
        coefficients[28 - 1] = F2::ONE;
        coefficients[17 - 1] = F2::ONE;
        coefficients[11 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }

    #[inline]
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        Gf45(rng.next_u64() & ((1 << 45) - 1))
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = (1 << 45) - 1;

    const MODULUS: u128 = 2;
    // This corresponds to the polynomial P(x) = x
    const GENERATOR: Self = Gf45(2);

    const ZERO: Self = Gf45(0);

    const ONE: Self = Gf45(1);

    #[inline]
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
    }
}

impl IsSubfieldOf<Gf45> for F2 {
    fn lift_into_superfield(&self) -> Gf45 {
        Gf45::ONE.multiply_by_prime_subfield(*self)
    }
}

field_ops!(Gf45);

#[cfg(test)]
test_field!(test_gf45, Gf45);
