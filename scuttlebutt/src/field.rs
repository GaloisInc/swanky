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
    + Default
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
    type PrimeField: FiniteField<
            PrimeField = Self::PrimeField,
            PolynomialFormNumCoefficients = generic_array::typenum::U1,
        > + IsSubfieldOf<Self>;
    /// When elements of this field are represented as a polynomial over the prime field,
    /// how many coefficients are needed?
    type PolynomialFormNumCoefficients: ArrayLength<Self::PrimeField> + ArrayLength<Self>;
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
    /// Generate a random non-zero field element.
    fn random_nonzero<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        loop {
            let out = Self::random(rng);
            if out != Self::ZERO {
                return out;
            }
        }
    }
    /// The generator for the multiplicative group.
    const GENERATOR: Self;
    /// The additive identity element.
    const ZERO: Self;
    /// The multiplicative identity element.
    const ONE: Self;
    /// The number of bits in the bit decomposition of any element of this finite field.
    ///
    /// This number should be equal to (for the field $`\textsf{GF}(p^r)`$):
    /// ```math
    /// \lceil\log_2(p)\rceil \cdot r
    /// ```
    ///
    /// See [`Self::bit_decomposition`] for the exact meaning of bit decomposition
    type NumberOfBitsInBitDecomposition: ArrayLength<bool>;
    /// Decompose the given field element into bits.
    ///
    /// This bit decompostion should be done according to [Weng et al., section 5](https://eprint.iacr.org/2020/925.pdf#section.5).
    ///
    /// Let $`p`$ be a positive prime. Let $`r`$ be a positive integer.
    /// Let $`m=\lceil\log_2 p\rceil`$, the number of bits needed to represent $`p`$.
    ///
    /// Let $`F = \textsf{GF}(p^r)`$ be the current field (the field represented by `Self`).
    ///
    /// Let $`v`$ be a vector of $`r \cdot m`$ elements of $`F`$.
    /// Let $`v = (v_0, v_1, \ldots, v_{rm}) \in F^{rm}`$.
    /// We define (don't worry about $`g`$, we're just keeping the syntax of the paper)
    /// $`\langle g,v\rangle \in F`$ using the polynomial representation of F, below:
    /// ```math
    /// \langle g, v \rangle(x) \coloneqq
    /// \sum\limits_{i=0}^{r-1} \left( x^i \cdot \sum\limits_{j=1}^{m-1}
    /// 2^j \cdot v_{i \cdot m + j}
    /// \right )
    /// ```
    ///
    /// Let $`f \in F`$.
    /// Let $`b \in \{0,1\}^{rm} \subseteq F^{rm}`$ (that is, a 0/1 vector where 0/1 are field
    /// elements of $`F`$), such that $`\langle g, b \rangle = f`$.
    ///
    /// Invoking the `bit_decomposition` function on `f` should yield the vector $`b`$ where a 0
    /// element of $`b`$ corresponds to `false` and a 1 element corresponds to `true`.
    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition>;
    /// Compute the multiplicative inverse of self.
    ///
    /// # Panics
    /// This function will panic if `*self == Self::zero()`
    fn inverse(&self) -> Self;

    // TODO: what should we do if n isn't secret.
    /// Compute `self` to the power of `n`.
    /// # Constant-Time
    /// This function will execute in constant-time, regardless of `n`'s value.
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

/// If `Self` implements `IsSubfieldOf<FE>`, then `Self` is a subfield of `FE`.
pub trait IsSubfieldOf<FE: FiniteField>: FiniteField {
    /// Homomorphically lift elements of `Self` into elements of `FE`.
    fn lift_into_superfield(&self) -> FE;
}
impl<FE: FiniteField> IsSubfieldOf<FE> for FE {
    fn lift_into_superfield(&self) -> FE {
        *self
    }
}

#[cfg(test)]
#[macro_use]
mod test_utils;

#[cfg(test)]
macro_rules! call_with_big_finite_fields {
    ($f:ident $(, $arg:expr)* $(,)?) => {{
        $f::<$crate::field::Fp>($($arg),*);
        $f::<$crate::field::Gf128>($($arg),*);
        $f::<$crate::field::Gf45>($($arg),*);
        $f::<$crate::field::Gf40>($($arg),*);
        $f::<$crate::field::F61p>($($arg),*);
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

        field_ops!($f, SUM_ALREADY_DEFINED);
    };

    // Compared to the previous pattern, `Sum` is missing and assumed
    // to be implemented by the field directly
    ( $f:ident, SUM_ALREADY_DEFINED) => {
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

pub(crate) fn standard_bit_decomposition<L: ArrayLength<bool>>(
    bits: u128,
) -> GenericArray<bool, L> {
    let mut out: GenericArray<bool, L> = Default::default();
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = (bits & (1 << (i as u128))) != 0;
    }
    out
}

mod fp;
pub use fp::{BiggerThanModulus, Fp};

mod f2;
pub use f2::{BiggerThanModulus as F2BiggerThanModulus, F2};

mod gf_2_128;
pub use gf_2_128::{Gf128, Gf128BytesDeserializationCannotFail};

mod gf_2_45;
pub use gf_2_45::{Gf45, Gf45ValueBiggerThanModulus};

mod gf_2_40;
pub use gf_2_40::{Gf40, Gf40ValueBiggerThanModulus};

mod f61p;
pub use f61p::F61p;

pub mod polynomial;
