//! This module has implementations for a specific prime finite field.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crate::{field::FiniteField, Block};
use generic_array::GenericArray;
use primitive_types::{U128, U256};
use rand_core::RngCore;
use std::{
    convert::TryFrom,
    hash::Hash,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
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
impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Fp {
    /// The prime field modulus: $2^{128} - 159$
    pub const MODULUS: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297;

    // This function is required by the uint_full_mul_reg macro
    #[inline(always)]
    const fn split_u128(a: u128) -> (u64, u64) {
        ((a >> 64) as u64, a as u64)
    }
}

impl FiniteField for Fp {
    /// There is a slight bias towards the range $[0,158]$.
    /// There is a $\frac{159}{2^128} \approx 4.6 \times 10^{-37}$ chance of seeing this bias.
    fn random<R: RngCore>(rng: &mut R) -> Self {
        // The backend::Fp::random(rng) function panics, so we don't use it.
        Self::try_from(
            ((u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())) % Self::MODULUS,
        )
        .unwrap()
    }

    fn zero() -> Self {
        Fp(0)
    }

    fn one() -> Self {
        Fp(1)
    }
    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = BiggerThanModulus;

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

    fn generator() -> Self {
        Fp(5)
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

impl std::iter::Sum for Fp {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Fp::zero(), |a, b| a + b)
    }
}

macro_rules! binop {
    ($trait:ident, $name:ident, $assign:ident) => {
        impl $trait<Fp> for Fp {
            type Output = Fp;

            #[inline]
            fn $name(mut self, rhs: Fp) -> Self::Output {
                self.$assign(rhs);
                self
            }
        }
        impl<'a> $trait<Fp> for &'a Fp {
            type Output = Fp;

            #[inline]
            fn $name(self, rhs: Fp) -> Self::Output {
                let mut this = self.clone();
                this.$assign(rhs);
                this
            }
        }
        impl<'a> $trait<&'a Fp> for Fp {
            type Output = Fp;

            #[inline]
            fn $name(mut self, rhs: &'a Fp) -> Self::Output {
                self.$assign(rhs);
                self
            }
        }
        impl<'a> $trait<&'a Fp> for &'a Fp {
            type Output = Fp;

            #[inline]
            fn $name(self, rhs: &'a Fp) -> Self::Output {
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
macro_rules! assign_op {
    ($tr:ident, $op:ident) => {
        impl $tr<Fp> for Fp {
            fn $op(&mut self, rhs: Fp) {
                self.$op(&rhs)
            }
        }
    };
}
assign_op!(AddAssign, add_assign);
assign_op!(SubAssign, sub_assign);
assign_op!(MulAssign, mul_assign);

impl Neg for Fp {
    type Output = Fp;

    fn neg(self) -> Self::Output {
        Fp::zero() - self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use quickcheck_macros::quickcheck;

    impl quickcheck::Arbitrary for Fp {
        fn arbitrary<RNG: RngCore>(mut g: &mut RNG) -> Fp {
            Fp::random(&mut g)
        }
    }

    macro_rules! test_binop {
        ($name:ident, $op:ident) => {
            #[cfg(test)]
            #[quickcheck]
            fn $name(mut a: Fp, b: Fp) -> bool {
                let mut x = BigUint::from(a.0);
                let y = BigUint::from(b.0);
                a.$op(&b);
                // This is a hack! That's okay, this is a test!
                if stringify!($op) == "sub_assign" {
                    x += BigUint::from(Fp::MODULUS);
                }
                x.$op(&y);
                x = x % BigUint::from(Fp::MODULUS);
                BigUint::from(a.0) == x
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    #[cfg(test)]
    test_field!(test_fp, Fp);

    #[quickcheck]
    fn check_pow(x: Fp, n: u128) -> bool {
        let m = BigUint::from(Fp::MODULUS);
        let exp = BigUint::from(n);
        let a = BigUint::from(u128::from(x));
        let left = BigUint::from(u128::from(x.pow(n)));
        left == a.modpow(&exp, &m)
    }
}
