use crate::field::{polynomial::Polynomial, BiggerThanModulus, FiniteField};
use generic_array::GenericArray;
use rand_core::RngCore;
use std::{
    convert::TryFrom,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(test)]
use proptest::prelude::*;

/// A finite field over the Mersenne Prime 2^61 - 1
#[derive(Clone, Copy, Eq, Debug, Hash)]
pub struct F61p(u64);

impl ConstantTimeEq for F61p {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for F61p {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F61p(u64::conditional_select(&a.0, &b.0, choice))
    }
}
impl FiniteField for F61p {
    type ByteReprLen = generic_array::typenum::U8;
    type FromBytesError = BiggerThanModulus;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        let buf = <[u8; 8]>::from(*bytes);
        let raw = u64::from_le_bytes(buf);
        if raw < Self::MODULUS as u64 {
            Ok(F61p(raw))
        } else {
            Err(BiggerThanModulus)
        }
    }

    #[inline]
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }

    type PrimeField = Self;
    type PolynomialFormNumCoefficients = generic_array::typenum::U1;

    #[inline]
    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        coeff[0]
    }

    #[inline]
    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        [*self].into()
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    #[inline]
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        self * pf
    }

    #[inline]
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        F61p(u64::from_le_bytes(<[u8; 8]>::try_from(&x[0..8]).unwrap()) & Self::MODULUS as u64)
    }

    #[inline]
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        F61p(rng.next_u64() & Self::MODULUS as u64)
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS - 1;
    const MODULUS: u128 = (1 << 61) - 1;
    // TODO: this generator might be wrong.
    const GENERATOR: Self = F61p(5);
    const ZERO: Self = F61p(0);
    const ONE: Self = F61p(1);
}

#[inline]
fn reduce(k: u128) -> u64 {
    // Based on https://ariya.io/2007/02/modulus-with-mersenne-prime
    let i = (k & F61p::MODULUS) + (k >> 61);
    u64::conditional_select(
        &(i as u64),
        &((i.wrapping_sub(F61p::MODULUS)) as u64),
        Choice::from((i >= F61p::MODULUS) as u8),
    )
}

impl AddAssign<&F61p> for F61p {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let a = self.0 as u128;
        let b = rhs.0 as u128;
        self.0 = reduce(a + b);
    }
}

impl SubAssign<&F61p> for F61p {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        // We add modulus so it can't overflow.
        let a = self.0 as u128 + Self::MODULUS;
        let b = rhs.0 as u128;
        self.0 = reduce(a - b);
    }
}

impl MulAssign<&F61p> for F61p {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let a = self.0 as u128;
        let b = rhs.0 as u128;
        self.0 = reduce(a * b);
    }
}

field_ops!(F61p);

#[cfg(test)]
test_field!(test_f61p, F61p);

#[cfg(test)]
proptest! {
    #[test]
    fn test_reduce(x in 0u128..((1 << (2 * 61))-1)) {
        assert_eq!(reduce(x) as u128, x % F61p::MODULUS);
    }
}

#[test]
fn test_generator() {
    assert_eq!(
        F61p::GENERATOR.pow(F61p::MULTIPLICATIVE_GROUP_ORDER),
        F61p::ONE
    );
}
