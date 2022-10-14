//! This module defines finite fields.

use crate::{field::polynomial::Polynomial, ring::FiniteRing};
use generic_array::{ArrayLength, GenericArray};
use std::ops::{Div, DivAssign};

/// Types that implement this trait are finite fields.
pub trait FiniteField: FiniteRing + DivAssign<Self> + Div<Self, Output = Self> {
    /// The prime-order subfield of the finite field.
    type PrimeField: PrimeFiniteField + IsSubfieldOf<Self>;
    /// When elements of this field are represented as a polynomial over the prime field,
    /// how many coefficients are needed?
    // TODO: rename this to degree
    type PolynomialFormNumCoefficients: ArrayLength<Self::PrimeField> + ArrayLength<Self>;
    /// Convert a polynomial over the prime field into a field element of the finite field.
    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self;
    /// Convert the field element into (coefficients of) a polynomial over the prime field.
    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>;
    // TODO: rename this to polynomial_modulus
    /// Multiplication over field elements should be reduced over this polynomial.
    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField>;
    /// A fused "lift from prime subfield and then multiply" operation. This operation can be much
    /// faster than manually lifting and then multiplying.
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self;

    /// The generator for the multiplicative group.
    const GENERATOR: Self;

    /// The number of bits in the bit decomposition of any element of this finite field.
    ///
    /// This number should be equal to (for the field $`\textsf{GF}(p^r)`$):
    /// ```math
    /// \lceil\log_2(p)\rceil \cdot r
    /// ```
    ///
    /// See [`Self::bit_decomposition`] for the exact meaning of bit decomposition
    type NumberOfBitsInBitDecomposition: ArrayLength<bool> + ArrayLength<F2>;
    /// Decompose the given field element into bits.
    ///
    /// This bit decomposition should be done according to [Weng et al., section 5](https://eprint.iacr.org/2020/925.pdf#section.5).
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
}

// TODO: so that we can break things into crates more easily, turn this into IsSuperfieldOf

/// If `Self` implements `IsSubfieldOf<FE>`, then `Self` is a subfield of `FE`.
pub trait IsSubfieldOf<FE: FiniteField>: FiniteField {
    /// Homomorphically lift elements of `Self` into elements of `FE`.
    fn lift_into_superfield(&self) -> FE;
    /// Multiply self by the superfield element `x`
    fn multiply_by_superfield(&self, x: FE) -> FE {
        self.lift_into_superfield() * x
    }
}
impl<FE: FiniteField> IsSubfieldOf<FE> for FE {
    fn lift_into_superfield(&self) -> FE {
        *self
    }
}

/// A `PrimeFiniteField` is a `FiniteField` with a prime modulus. In this case
/// the field is isomorphic to integers modulo prime `p`.
pub trait PrimeFiniteField:
    FiniteField<PolynomialFormNumCoefficients = generic_array::typenum::U1, PrimeField = Self>
    + std::convert::TryFrom<u128>
{
}

/// The error which occurs if the inputted value or bit pattern doesn't correspond to a field
/// element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An error with no inhabitants, for when a field cannot fail to deserialize.
#[derive(Clone, Copy, Debug)]
pub enum BytesDeserializationCannotFail {}
impl std::fmt::Display for BytesDeserializationCannotFail {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        unreachable!("Self has no values that inhabit it")
    }
}
impl std::error::Error for BytesDeserializationCannotFail {}

macro_rules! num_traits_zero_and_one {
    ($f: ident) => {
        impl num_traits::Zero for $f {
            #[inline]
            fn zero() -> Self {
                <$f as crate::field::FiniteRing>::ZERO
            }
            #[inline]
            fn is_zero(&self) -> bool {
                *self == <$f as crate::field::FiniteRing>::ZERO
            }
        }

        impl num_traits::One for $f {
            #[inline]
            fn one() -> Self {
                <$f as crate::field::FiniteRing>::ONE
            }
            #[inline]
            fn is_one(&self) -> bool {
                *self == <$f as crate::field::FiniteRing>::ONE
            }
        }
    };
}
// So we can use the macro within another macro.
pub(crate) use num_traits_zero_and_one;

#[cfg(test)]
#[macro_use]
mod test_utils;

#[cfg(test)]
macro_rules! call_with_big_finite_fields {
    ($f:ident $(, $arg:expr)* $(,)?) => {{
        $f::<$crate::field::F61p>($($arg),*);
        $f::<$crate::field::F64b>($($arg),*);
        $f::<$crate::field::F128b>($($arg),*);
        $f::<$crate::field::F40b>($($arg),*);
        $f::<$crate::field::F45b>($($arg),*);
        $f::<$crate::field::F56b>($($arg),*);
        $f::<$crate::field::F63b>($($arg),*);
        #[cfg(feature = "ff")]
        $f::<$crate::field::F128p>($($arg),*);
        #[cfg(feature = "ff")]
        $f::<$crate::field::F384p>($($arg),*);
        #[cfg(feature = "ff")]
        $f::<$crate::field::F384q>($($arg),*);
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
    ($f:ident $($tt:tt)*) => {
        crate::ring::ring_ops!($f $($tt)*);

        binop!(Div, div, std::ops::DivAssign::div_assign, $f);
        assign_op!(DivAssign, div_assign, $f);

        impl<'a> std::ops::DivAssign<&'a $f> for $f {
            fn div_assign(&mut self, rhs: &Self) {
                *self *= rhs.inverse();
            }
        }
    };
}

/// Bit decomposition of `bits` into an array.
pub(crate) fn standard_bit_decomposition<L: ArrayLength<bool>>(
    bits: u128,
) -> GenericArray<bool, L> {
    let mut out: GenericArray<bool, L> = Default::default();
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = (bits & (1 << (i as u128))) != 0;
    }
    out
}

mod f2;
pub use f2::F2;

mod f128b;
pub use f128b::F128b;

mod f64b;
pub use f64b::F64b;

mod small_binary_fields;
pub use small_binary_fields::{F40b, F45b, F56b, F63b, SmallBinaryField};

mod f61p;
pub use f61p::F61p;

mod f2_19x3_26;
pub use f2_19x3_26::F2_19x3_26;

#[cfg(feature = "ff")]
mod prime_field_using_ff;
#[cfg(feature = "ff")]
pub use prime_field_using_ff::{F128p, F256p, F384p, F384q, Fbls12381, Fbn254};

pub mod polynomial;

mod monty;

pub mod fft;
