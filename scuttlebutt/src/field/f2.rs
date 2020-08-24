//! This module has implementations for a specific prime finite field.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crate::field::FiniteField;
use generic_array::GenericArray;
use rand::Rng;
use rand_core::RngCore;
use std::{
    convert::{TryFrom, TryInto},
    hash::Hash,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the prime-order finite field $\textsf{GF}(2^{128} - 159)$
///
/// This is called `F2` because it is our "common" prime-order finite field.
#[derive(Debug, Eq, Clone, Copy, Hash)]
pub struct F2(u8);

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
impl PartialEq for F2 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl F2 {
    /// The prime field modulus: $2^{128} - 159$
    pub const MODULUS: u8 = 2;
}

impl FiniteField for F2 {
    /// There is a slight bias towards the range $[0,158]$.
    /// There is a $\frac{159}{2^128} \approx 4.6 \times 10^{-37}$ chance of seeing this bias.
    fn random<R: RngCore>(rng: &mut R) -> Self {
        // The backend::F2::random(rng) function panics, so we don't use it.
        F2(u8::from(rng.gen::<bool>()))
    }

    fn zero() -> Self {
        F2(0)
    }

    fn one() -> Self {
        F2(1)
    }
    type R = generic_array::typenum::U1;
    type PrimeSubField = F2;
    type ByteReprLen = generic_array::typenum::U1;
    type FromBytesError = BiggerThanModulus;

    /// If you put random bytes into here, while it's _technically_ biased, there's only a tiny
    /// chance that you'll get biased output.
    fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
        F2::try_from(u8::from_le_bytes(*buf.as_ref()))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        u8::from(*self).to_le_bytes().into()
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS as u128 - 1;

    fn generator() -> Self {
        F2(1)
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

impl TryFrom<u8> for F2 {
    type Error = BiggerThanModulus;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < Self::MODULUS {
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

impl std::iter::Sum for F2 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(F2::zero(), |a, b| a + b)
    }
}

macro_rules! binop {
    ($trait:ident, $name:ident, $assign:ident) => {
        impl $trait<F2> for F2 {
            type Output = F2;

            #[inline]
            fn $name(mut self, rhs: F2) -> Self::Output {
                self.$assign(rhs);
                self
            }
        }
        impl<'a> $trait<F2> for &'a F2 {
            type Output = F2;

            #[inline]
            fn $name(self, rhs: F2) -> Self::Output {
                let mut this = self.clone();
                this.$assign(rhs);
                this
            }
        }
        impl<'a> $trait<&'a F2> for F2 {
            type Output = F2;

            #[inline]
            fn $name(mut self, rhs: &'a F2) -> Self::Output {
                self.$assign(rhs);
                self
            }
        }
        impl<'a> $trait<&'a F2> for &'a F2 {
            type Output = F2;

            #[inline]
            fn $name(self, rhs: &'a F2) -> Self::Output {
                let mut this = self.clone();
                this.$assign(rhs);
                this
            }
        }
    };
}

binop!(Add, add, add_assign);
binop!(Sub, sub, sub_assign);
binop!(Mul, mul, mul_assign);
// TODO: there's definitely room for optimization. We don't need to use the full mod algorithm here.
impl AddAssign<&F2> for F2 {
    fn add_assign(&mut self, rhs: &F2) {
        let mut raw_sum = (self.0).checked_add(rhs.0).unwrap();
        if raw_sum >= Self::MODULUS {
            raw_sum -= Self::MODULUS;
        }
        self.0 = raw_sum;
    }
}

impl SubAssign<&F2> for F2 {
    fn sub_assign(&mut self, rhs: &F2) {
        let mut raw_diff = self.0 + Self::MODULUS.checked_sub(rhs.0).unwrap();
        if raw_diff >= Self::MODULUS {
            raw_diff -= Self::MODULUS;
        }
        debug_assert!(raw_diff < Self::MODULUS);
        self.0 = raw_diff.to_be().try_into().unwrap();
    }
}

impl MulAssign<&F2> for F2 {
    fn mul_assign(&mut self, rhs: &F2) {
        let raw_prod = (self.0) * rhs.0;
        self.0 = raw_prod % Self::MODULUS;
    }
}
macro_rules! assign_op {
    ($tr:ident, $op:ident) => {
        impl $tr<F2> for F2 {
            fn $op(&mut self, rhs: F2) {
                self.$op(&rhs)
            }
        }
    };
}
assign_op!(AddAssign, add_assign);
assign_op!(SubAssign, sub_assign);
assign_op!(MulAssign, mul_assign);

impl Neg for F2 {
    type Output = F2;

    fn neg(self) -> Self::Output {
        F2::zero() - self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use quickcheck_macros::quickcheck;

    impl quickcheck::Arbitrary for F2 {
        fn arbitrary<RNG: RngCore>(mut g: &mut RNG) -> F2 {
            F2::random(&mut g)
        }
    }

    macro_rules! test_binop {
        ($name:ident, $op:ident) => {
            #[cfg(test)]
            #[quickcheck]
            fn $name(mut a: F2, b: F2) -> bool {
                let mut x = a.0;
                let y = b.0;
                a.$op(&b);
                // This is a hack! That's okay, this is a test!
                if stringify!($op) == "sub_assign" {
                    x += F2::MODULUS;
                }
                x.$op(&y);
                x = x % F2::MODULUS;
                a.0 == x
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    #[cfg(test)]
    test_field!(test_f2, F2);
    #[quickcheck]
    fn check_pow(x: F2, n: u128) -> bool {
        let m = BigUint::from(F2::MODULUS);
        let exp = BigUint::from(n);
        let a = BigUint::from(u8::from(x));
        let left = BigUint::from(u8::from(x.pow(n)));
        left == a.modpow(&exp, &m)
    }
}
