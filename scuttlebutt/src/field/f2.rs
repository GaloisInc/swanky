//! This module has implementations for a finite field with modulus 2.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crate::field::{polynomial::Polynomial, FiniteField, PrimeFiniteField};
use generic_array::GenericArray;
use rand_core::RngCore;
use std::{
    convert::TryFrom,
    hash::Hash,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the prime-order finite field $\textsf{GF}(2).$
#[derive(Debug, Eq, Clone, Copy, Hash)]
pub struct F2(pub(crate) u8);

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

impl FiniteField for F2 {
    /// This uniformly generates a field element either 0 or 1 for `F2` type.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        // Grab the LSBit from a 32-bit integer. Rand's boolean generation doesn't do this,
        // since it's concerend about insecure random number generators.
        F2((rng.next_u32() & 1) as u8)
    }

    const ZERO: Self = F2(0);

    const ONE: Self = F2(1);

    type ByteReprLen = generic_array::typenum::U1;
    type FromBytesError = BiggerThanModulus;

    fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
        F2::try_from(u8::from_le_bytes(*buf.as_ref()))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        u8::from(*self).to_le_bytes().into()
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS as u128 - 1;

    const GENERATOR: Self = F2(1);

    type PrimeField = Self;
    type PolynomialFormNumCoefficients = generic_array::typenum::U1;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        coeff[0]
    }

    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        let mut value = u128::from_le_bytes(*x);
        value &= 1;
        F2(value as u8)
    }

    /// The prime field modulus: $2$
    const MODULUS: u128 = 2;

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

impl PrimeFiniteField for F2 {
    fn mod2(&self) -> Self {
        return F2(self.0 % 2);
    }
}

/// The error which occurs if the inputted `u8` or bit pattern doesn't correspond to a field
/// element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u8> for F2 {
    type Error = BiggerThanModulus;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < Self::MODULUS as u8 {
            Ok(F2(value))
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

field_ops!(F2);

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
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
                        x += F2::MODULUS as u8;
                    }
                    x.$op(&y);
                    x = x % F2::MODULUS as u8;
                    assert_eq!(a.0, x);
                }
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    test_field!(test_f2, F2);

    proptest! {
        #[test]
        fn check_pow(x in any::<F2>(), n in any::<u128>()) {
            let m = BigUint::from(F2::MODULUS);
            let exp = BigUint::from(n);
            let a = BigUint::from(u8::from(x));
            let left = BigUint::from(u8::from(x.pow(n)));
            assert_eq!(left, a.modpow(&exp, &m));
        }
    }
}
