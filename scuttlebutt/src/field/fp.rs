//! This module has implementations for a specific prime finite field.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crate::{
    field::{polynomial::Polynomial, FiniteField},
    Block,
};
use generic_array::GenericArray;
use primitive_types::{U128, U256};
use rand_core::RngCore;
use std::{
    convert::TryFrom,
    hash::Hash,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the prime-order finite field $\textsf{GF}(2^{128} - 159)$
///
/// This is called `Fp` because it is our "common" prime-order finite field.
#[derive(Debug, Eq, Clone, Copy, Hash)]
pub struct Fp(u128);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl Fp {
    // This function is required by the uint_full_mul_reg macro
    #[inline(always)]
    const fn split_u128(a: u128) -> (u64, u64) {
        ((a >> 64) as u64, a as u64)
    }
}

impl FiniteField for Fp {
    /// There is a slight bias towards the range $`[0,158]`$.
    /// There is a $`\frac{159}{2^128} \approx 4.6 \times 10^{-37}`$ chance of seeing this bias.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes[..]);
        Self::try_from(u128::from_le_bytes(bytes) % Self::MODULUS).unwrap()
    }

    const ZERO: Self = Fp(0);

    const ONE: Self = Fp(1);

    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = BiggerThanModulus;

    /// If the given value is greater than the modulus, then reduce the value by the modulus. Although,
    /// the output of this function is biased in that case, it is less probability that the number greater than the
    /// modulus.
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        let mut value = u128::from_le_bytes(*x);
        if value > Self::MODULUS {
            value %= Self::MODULUS
        }
        Fp(value)
    }
    /// If you put random bytes into here, while it's _technically_ biased, there's only a tiny
    /// chance that you'll get biased output.
    fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
        Fp::try_from(u128::from_le_bytes(*buf.as_ref()))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        u128::from(*self).to_le_bytes().into()
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS - 1;

    /// The prime field modulus: $2^{128} - 159$
    const MODULUS: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297;

    const GENERATOR: Self = Fp(5);

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
}

/// The error which occurs if the inputted `u128` or bit pattern doesn't correspond to a field
/// element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u128> for Fp {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < Self::MODULUS {
            Ok(Fp(value))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

impl TryFrom<Block> for Fp {
    type Error = BiggerThanModulus;

    fn try_from(value: Block) -> Result<Self, Self::Error> {
        let val = u128::from(value);
        Fp::try_from(val)
    }
}

/// This returns a canonical/reduced form of the field element.
impl From<Fp> for u128 {
    #[inline]
    fn from(x: Fp) -> Self {
        x.0
    }
}

// TODO: there's definitely room for optimization. We don't need to use the full mod algorithm here.
impl AddAssign<&Fp> for Fp {
    fn add_assign(&mut self, rhs: &Fp) {
        let mut raw_sum = U256::from(self.0).checked_add(U256::from(rhs.0)).unwrap();
        if raw_sum >= U256::from(Self::MODULUS) {
            raw_sum -= U256::from(Self::MODULUS);
        }
        self.0 = raw_sum.as_u128();
    }
}

impl SubAssign<&Fp> for Fp {
    fn sub_assign(&mut self, rhs: &Fp) {
        let mut raw_diff = (U256::from(self.0) + U256::from(Self::MODULUS))
            .checked_sub(U256::from(rhs.0))
            .unwrap();
        if raw_diff >= U256::from(Self::MODULUS) {
            raw_diff -= U256::from(Self::MODULUS);
        }
        debug_assert!(raw_diff < U256::from(Self::MODULUS));
        self.0 = raw_diff.as_u128();
    }
}

impl MulAssign<&Fp> for Fp {
    fn mul_assign(&mut self, rhs: &Fp) {
        let raw_prod = U256(uint::uint_full_mul_reg!(
            U128,
            2,
            U128::from(self.0),
            U128::from(rhs.0)
        ));
        self.0 = (raw_prod % U256::from(Self::MODULUS)).as_u128();
    }
}

field_ops!(Fp);

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use proptest::prelude::*;

    fn any_f() -> impl Strategy<Value = Fp> {
        any::<u128>().prop_map(|x| Fp(x % Fp::MODULUS))
    }

    macro_rules! test_binop {
        ($name:ident, $op:ident) => {
            proptest! {
                #[test]
                fn $name(mut a in any_f(), b in any_f()) {
                    let mut x = BigUint::from(a.0);
                    let y = BigUint::from(b.0);
                    a.$op(&b);
                    // This is a hack! That's okay, this is a test!
                    if stringify!($op) == "sub_assign" {
                        x += BigUint::from(Fp::MODULUS);
                    }
                    x.$op(&y);
                    x = x % BigUint::from(Fp::MODULUS);
                    assert_eq!(BigUint::from(a.0), x);
                }
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    #[cfg(test)]
    test_field!(test_fp, Fp);

    proptest! {
        #[test]
        fn check_pow(x in any_f(), n in any::<u128>()) {
            let m = BigUint::from(Fp::MODULUS);
            let exp = BigUint::from(n);
            let a = BigUint::from(u128::from(x));
            let left = BigUint::from(u128::from(x.pow(n)));
            assert_eq!(left, a.modpow(&exp, &m));
        }
    }
}
