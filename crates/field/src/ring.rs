//! This module defines finite rings.

use rand::Rng;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_serialization::CanonicalSerialize;

/// Types that implement this trait are finite rings.
pub trait FiniteRing:
    'static
    + Clone
    + Copy
    + Send
    + Sync
    + Default
    + Debug
    + Eq
    + PartialEq
    + Hash
    + Sized
    + ConstantTimeEq
    + ConditionallySelectable
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Neg<Output = Self>
    + std::iter::Sum
    + std::iter::Product
    + num_traits::Zero
    + num_traits::One
    + CanonicalSerialize
{
    /// Construct an element from the given uniformly chosen random bytes.
    fn from_uniform_bytes(x: &[u8; 16]) -> Self;
    /// Generate a random element.
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self;
    /// Generate a random non-zero element.
    fn random_nonzero<R: Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let out = Self::random(rng);
            if out != Self::ZERO {
                return out;
            }
        }
    }

    /// The additive identity element.
    const ZERO: Self;
    /// The multiplicative identity element.
    const ONE: Self;

    /// Compute `self` to the power of `n`.
    ///
    /// # Constant-Time
    /// This function will execute in constant-time, regardless of `n`'s value.
    fn pow(&self, n: u128) -> Self {
        self.pow_bounded(n, 128)
    }

    /// Compute `self` to the power of `n`, where `n` is guaranteed to be `<= 2^bound`.
    ///
    /// # Constant-Time
    /// This function is constant time in `n`, but _not_ constant time in `bound`.
    #[inline]
    fn pow_bounded(&self, n: u128, bound: u16) -> Self {
        debug_assert!(bound <= 128);
        debug_assert_eq!(
            // Avoid overflow panic if `bound == 128`
            if bound != 128 { n >> bound } else { 0 },
            0
        );
        let mut r0 = Self::ONE;
        let mut r1 = *self;
        for i in (0..bound).rev() {
            // This is equivalent to the following code, but constant-time:
            /*if n & (1 << i) == 0 {
                r1.mul_assign(r0);
                r0.mul_assign(r0);
            } else {
                r0.mul_assign(r1);
                r1.mul_assign(r1);
            }*/
            let bit_is_high = Choice::from((n & (1 << i) != 0) as u8);
            let operand = Self::conditional_select(&r0, &r1, bit_is_high);
            r0 *= operand;
            r1 *= operand;
        }
        r0
    }

    /// Compute `self` to the power of `n`, **in non-constant time**.
    fn pow_var_time(&self, n: u128) -> Self {
        let mut acc = Self::ONE;
        let mut b = *self;
        let mut n = n;

        while n != 0 {
            if n & 0b1 == 0b1 {
                acc = b * acc;
            }
            b = b * b;
            n >>= 1;
        }

        acc
    }
}

/// Indicates that `Self` is a sub ring of `R`.
pub trait IsSubRingOf<R: FiniteRing>: FiniteRing + Mul<R, Output = R> + Into<R> {}
impl<R: FiniteRing> IsSubRingOf<R> for R {}

/// Automatically implement boilerplate ring operations for the given type.
///
/// This macro is used like `ring_ops!(my_type)`. If `my_type` already has a [`std::iter::Sum`]
/// implementation, this macro can be asked to not generate an implementation of `Sum` via
/// `ring_ops!(my_type, SUM_ALREADY_DEFINED)`.
#[macro_export]
macro_rules! ring_ops {
    ($f:ident) => {
        impl std::iter::Sum for $f {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold($f::ZERO, std::ops::Add::add)
            }
        }

        $crate::ring_ops!($f, SUM_ALREADY_DEFINED);
    };

    // Compared to the previous pattern, `Sum` is missing and assumed
    // to be implemented by the field directly
    ($f:ident, SUM_ALREADY_DEFINED) => {
        impl PartialEq for $f {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl Default for $f {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl std::iter::Product for $f {
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold($f::ONE, std::ops::Mul::mul)
            }
        }
        $crate::ring_ops!(@binop Add, add, std::ops::AddAssign::add_assign, $f);
        $crate::ring_ops!(@binop Sub, sub, std::ops::SubAssign::sub_assign, $f);
        $crate::ring_ops!(@binop Mul, mul, std::ops::MulAssign::mul_assign, $f);
        $crate::ring_ops!(@assign_op AddAssign, add_assign, $f);
        $crate::ring_ops!(@assign_op SubAssign, sub_assign, $f);
        $crate::ring_ops!(@assign_op MulAssign, mul_assign, $f);

        impl $crate::__macro_export::num_traits::Zero for $f {
            #[inline]
            fn zero() -> Self {
                <$f as $crate::FiniteRing>::ZERO
            }
            #[inline]
            fn is_zero(&self) -> bool {
                *self == <$f as $crate::FiniteRing>::ZERO
            }
        }

        impl $crate::__macro_export::num_traits::One for $f {
            #[inline]
            fn one() -> Self {
                <$f as $crate::FiniteRing>::ONE
            }
            #[inline]
            fn is_one(&self) -> bool {
                *self == <$f as $crate::FiniteRing>::ONE
            }
        }

        impl std::ops::Neg for $f {
            type Output = $f;

            fn neg(self) -> Self::Output {
                $f::ZERO - self
            }
        }

        impl $crate::__macro_export::rand::distributions::Distribution<$f>
            for rand::distributions::Standard
        {
            fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> $f {
                <$f>::random(rng)
            }
        }

        $crate::__macro_export::swanky_serialization::derive_serde_via_canonical_serialize!($f);
    };
    (@assign_op $tr:ident, $op:ident, $f:ident) => {
        impl std::ops::$tr<$f> for $f {
            #[inline]
            #[allow(unused_imports)]
            fn $op(&mut self, rhs: $f) {
                use std::ops::$tr;
                self.$op(&rhs)
            }
        }
    };
    (@binop $trait:ident, $name:ident, $assign:path, $f:ident) => {
        impl std::ops::$trait<$f> for $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(mut self, rhs: $f) -> Self::Output {
                use std::ops::$trait;
                $assign(&mut self, rhs);
                self
            }
        }
        impl<'a> std::ops::$trait<$f> for &'a $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(self, rhs: $f) -> Self::Output {
                use std::ops::$trait;
                let mut this = self.clone();
                $assign(&mut this, rhs);
                this
            }
        }
        impl<'a> std::ops::$trait<&'a $f> for $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(mut self, rhs: &'a $f) -> Self::Output {
                use std::ops::$trait;
                $assign(&mut self, rhs);
                self
            }
        }
        impl<'a> std::ops::$trait<&'a $f> for &'a $f {
            type Output = $f;

            #[inline]
            fn $name(self, rhs: &'a $f) -> Self::Output {
                let mut this = self.clone();
                $assign(&mut this, rhs);
                this
            }
        }
    };
}
