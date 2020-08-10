//! This module has implementations for specific finite fields.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use primitive_types::{U128, U256};
use rand_core::{CryptoRng, RngCore};
use std::{
    convert::TryFrom,
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the prime-order finite field $\textsf{GF}(2^{128} - 159)$
///
/// This is called `Fp` because it is our "common" prime-order finite field.
#[derive(Debug, Eq, Clone, Copy)]
pub struct Fp(u128);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(other.to_bytes().as_ref())
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
impl Hash for Fp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        u128::from(*self).hash(state)
    }
}

impl Fp {
    /// The prime field modulus: $2^{128} - 159$
    pub const MODULUS: u128 = 340282366920938463463374607431768211297;

    /// Generate an almost uniformly random field element.
    ///
    /// There is a slight bias towards the range $[0,158]$.
    /// There is a $\frac{159}{2^128} \approx 4.6 \times 10^{-37}$ chance of seeing this bias.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        // The backend::Fp::random(rng) function panics, so we don't use it.
        Self::try_from(
            ((u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())) % Self::MODULUS,
        )
        .unwrap()
    }

    pub fn zero() -> Self {
        Fp(0)
    }
    pub fn one() -> Self {
        Fp(1)
    }

    /// If you put random bytes into here, while it's _technically_ biased, there's only a tiny
    /// chance that you'll get biased output.
    pub fn from_bytes(buf: [u8; 16]) -> Result<Self, BiggerThanModulus> {
        Fp::try_from(u128::from_le_bytes(buf))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    pub fn to_bytes(&self) -> [u8; 16] {
        u128::from(*self).to_le_bytes()
    }

    // This function is required by the uint_full_mul_reg macro
    #[inline(always)]
    const fn split_u128(a: u128) -> (u64, u64) {
        ((a >> 64) as u64, a as u64)
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

macro_rules! test_binop {
    ($name:ident, $op:ident) => {
        #[cfg(test)]
        #[quickcheck_macros::quickcheck]
        fn $name(a: u128, b: u128) -> bool {
            use num_bigint::BigUint;
            let mut a = Fp::try_from(a % Fp::MODULUS).unwrap();
            let b = Fp::try_from(b % Fp::MODULUS).unwrap();
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
