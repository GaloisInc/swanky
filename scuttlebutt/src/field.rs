//! This module defines finite fields.

use crate::field::polynomial::Polynomial;
use generic_array::{ArrayLength, GenericArray};
use rand_core::RngCore;
use std::{
    fmt::Debug,
    hash::Hash,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
/// Types that implement this trait are finite field elements.
pub trait FiniteField:
    'static
    + Send
    + Sync
    + Hash
    + Debug
    + PartialEq
    + Eq
    + Sized
    + ConstantTimeEq
    + ConditionallySelectable
    + Clone
    + Copy
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + DivAssign<Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + Neg<Output = Self>
    + std::iter::Sum
    + std::iter::Product
{
    /// The number of bytes in the byte representation for this field element.
    type ByteReprLen: ArrayLength<u8>;
    /// The error that can result from trying to decode an invalid byte sequence.
    type FromBytesError: std::error::Error + Send + Sync + 'static;
    /// Deserialize a field element from a byte array.
    ///
    /// NOTE: for security purposes, this function will accept exactly one byte sequence for each
    /// field element.
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError>;
    /// Serialize a field element into a byte array.
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen>;

    /// The prime-order subfield of the finite field.
    type PrimeField: FiniteField;
    /// When elements of this field are represented as a polynomial over the prime field,
    /// how many coefficients are needed?
    type PolynomialFormNumCoefficients: ArrayLength<Self::PrimeField>;
    /// Convert a polynomial over the prime field into a field element of the finite field.
    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self;
    /// Convert the field element into (coefficients of) a polynomial over the prime field.
    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>;
    /// Multiplication over field elements should be reduced over this polynomial.
    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField>;
    /// A fused "lift from prime subfield and then multiply" operation. This operation can be much
    /// faster than manually lifting and then multiplying.
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self;
    /// Construct a field element from the given uniformly chosen random bytes.
    fn from_uniform_bytes(x: &[u8; 16]) -> Self;
    /// Generate a random field element.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self;
    /// The order of the multiplicative group
    // TODO: we'll want a better number type than u128 if the fields get bigger.
    const MULTIPLICATIVE_GROUP_ORDER: u128;
    /// The modulus of the prime sub-field.
    const MODULUS: u128;
    /// The generator for the multiplicative group.
    const GENERATOR: Self;
    /// The additive identity element.
    const ZERO: Self;
    /// The multiplicative identity element.
    const ONE: Self;
    /// Compute the multiplicative inverse of self.
    ///
    /// # Panics
    /// This function will panic if *self == Self::zero()
    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        // NOTE: this only works for GF(p^n)
        self.pow(Self::MULTIPLICATIVE_GROUP_ORDER - 1)
    }
    /// Computing `pow` using Montgomery's ladder technique.
    fn pow(&self, n: u128) -> Self {
        let mut r0 = Self::ONE;
        let mut r1 = *self;
        for i in (0..128).rev() {
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
}

#[cfg(test)]
#[macro_use]
mod test_utils;

#[cfg(test)]
macro_rules! call_with_big_finite_fields {
    ($f:ident $(, $arg:expr)* $(,)?) => {{
        $f::<$crate::field::Fp>($($arg),*);
        //$f::<$crate::field::Gf128>($($arg),*);
    }};
}

#[cfg(test)]
macro_rules! call_with_finite_field {
    ($f:ident $(, $arg:expr)* $(,)?) => {{
        call_with_big_finite_fields!($f$(,$arg)*);
        $f::<$crate::field::F2>($($arg),*);
    }};
}

macro_rules! assign_op {
    ($tr:ident, $op:ident, $f:ident) => {
        impl std::ops::$tr<$f> for $f {
            #[inline]
            #[allow(unused_imports)]
            fn $op(&mut self, rhs: $f) {
                use std::ops::$tr;
                self.$op(&rhs)
            }
        }
    };
}

macro_rules! binop {
    ($trait:ident, $name:ident, $assign:path, $f:ident) => {
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

macro_rules! field_ops {
    ($f:ident) => {
        impl std::iter::Sum for $f {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold($f::ZERO, std::ops::Add::add)
            }
        }

        field_ops!($f, "SUM_ALREADY_DEFINED");
    };

    // Compared to the previous pattern, `Sum` is missing and assumed
    // to be implemented by the field directly
    ( $f:ident, $sum_already_defined:expr ) => {
        impl PartialEq for $f {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl std::iter::Product for $f {
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold($f::ONE, std::ops::Mul::mul)
            }
        }
        binop!(Add, add, std::ops::AddAssign::add_assign, $f);
        binop!(Sub, sub, std::ops::SubAssign::sub_assign, $f);
        binop!(Mul, mul, std::ops::MulAssign::mul_assign, $f);
        binop!(Div, div, std::ops::DivAssign::div_assign, $f);
        assign_op!(AddAssign, add_assign, $f);
        assign_op!(SubAssign, sub_assign, $f);
        assign_op!(MulAssign, mul_assign, $f);
        assign_op!(DivAssign, div_assign, $f);

        impl std::ops::Neg for $f {
            type Output = $f;

            fn neg(self) -> Self::Output {
                $f::ZERO - self
            }
        }

        impl<'a> std::ops::DivAssign<&'a $f> for $f {
            fn div_assign(&mut self, rhs: &Self) {
                *self *= rhs.inverse();
            }
        }
    };
}

mod fp;
pub use fp::{BiggerThanModulus, Fp};

mod f2;
pub use f2::{BiggerThanModulus as F2BiggerThanModulus, F2};

mod gf_2_128;
pub use gf_2_128::{Gf128, Gf128BytesDeserializationCannotFail};

mod f61p;
pub use f61p::F61p;

pub mod polynomial;
