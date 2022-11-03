//! This module defines finite fields.

use crate::{
    field::polynomial::Polynomial,
    ring::{FiniteRing, IsSubRingOf}, generic_array_length::AnyArrayLength,
};
use generic_array::{ArrayLength, GenericArray};
use std::ops::{Div, DivAssign};

/// Types that implement this trait are finite fields.
pub trait FiniteField: FiniteRing + DivAssign<Self> + Div<Self, Output = Self> {
    /// The prime-order subfield of the finite field.
    type PrimeField: PrimeFiniteField + IsSubFieldOf<Self>;
    /// Multiplication over field elements should be reduced over this polynomial.
    fn polynomial_modulus() -> Polynomial<Self::PrimeField>;

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
    /// This function will panic if `*self == Self::ZERO`
    fn inverse(&self) -> Self;

    /// Decompose `self` into an array of `T` elements where `T` is a subfield of `Self`.
    ///
    /// See [`IsSubFieldOf`] for more info.
    #[inline]
    fn decompose<T: FiniteField + IsSubFieldOf<Self>>(&self) -> GenericArray<T, DegreeModulo<T, Self>> {
        T::decompose_superfield(self)
    }
    /// Create a field element from an array of subfield `T` elements.
    ///
    /// See [`IsSubFieldOf`] for more info.
    #[inline]
    fn from_subfield<T: FiniteField + IsSubFieldOf<Self>>(arr: &GenericArray<T, DegreeModulo<T, Self>>) -> Self {
        T::form_superfield(arr)
    }
}

/// The degree, $`r`$ of a finite field.
///
/// Where `Self` is $`\textsf{GF(p^r)}`$
pub type Degree<FE> = DegreeModulo<<FE as FiniteField>::PrimeField, FE>;

/// The relative degree between two Finite Fields.
///
/// Let $`A`$ be a subfield of $`B`$. `DegreeModulo<A, B>` is `DegreeModulo` as defined by
/// [`IsSubFieldOf`].
pub type DegreeModulo<A, B> = <A as IsSubFieldOf<B>>::DegreeModulo;

/// Denotes that `Self` is a subfield of `FE`.
/// 
/// All finite fields can be written as $`\textsf{GF}(p^r)`$ where $`p`$ is prime.
/// 
/// Let the finite field $`A`$ denote `Self` and $`B`$ denote `FE`.
///
/// If $`A`$ is a subfield of $`B`$, it's true that
/// 1. When $`A`$ and $`B`$ are written in the $`\textsf{GF}(p^r)`$ form, their primes are equal.
/// 2. $`r_A \vert r_B`$
///
/// Let $`n`$ be $`\frac{r_B}{r_A}`$.
///
/// $`B`$ is isomorphic to the set of polynomials of maximum degree $`n`$ where coefficients are
/// taken from $`A`$. To put it another way, we can represent $`B`$ as vectors containing $`n`$
/// $`A`$ values.
///
/// # Alternatives
/// These methods exist on the _subfield_ type, which is not a natural API. You may prefer using
/// [`FiniteField::decompose`], [`FiniteField::from_subfield`], or the type alias [`DegreeModulo`].
pub trait IsSubFieldOf<FE: FiniteField>: FiniteField + IsSubRingOf<FE> {
    /// The value $`n`$ from above.
    type DegreeModulo: ArrayLength<Self> + AnyArrayLength;
    /// Turn `FE` into an array of `Self`, a subfield of `FE`.
    fn decompose_superfield(fe: &FE) -> GenericArray<Self, Self::DegreeModulo>;
    /// Homomorphically lift an array of `Self` into an `FE`.
    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> FE;
}
impl<FE: FiniteField> IsSubFieldOf<FE> for FE {
    type DegreeModulo = generic_array::typenum::U1;
    #[inline]
    fn decompose_superfield(fe: &FE) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from([*fe])
    }
    #[inline]
    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> FE {
        components[0]
    }
}

/// A `PrimeFiniteField` is a `FiniteField` with a prime modulus. In this case
/// the field is isomorphic to integers modulo prime `p`.
pub trait PrimeFiniteField:
    FiniteField<PrimeField = Self> + IsSubFieldOf<Self, DegreeModulo = generic_array::typenum::U1> + std::convert::TryFrom<u128>
{
}

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

macro_rules! field_ops {
    ($f:ident $($tt:tt)*) => {
        crate::ring::ring_ops!($f $($tt)*);

        $crate::ops::binop!(Div, div, std::ops::DivAssign::div_assign, $f);
        $crate::ops::assign_op!(DivAssign, div_assign, $f);

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

#[cfg(feature = "ff")]
mod prime_field_using_ff;
#[cfg(feature = "ff")]
pub use prime_field_using_ff::{F128p, F256p, F384p, F384q, F400p, Fbls12381, Fbn254};
#[cfg(feature = "ff")]
mod f2e19x3e26;
#[cfg(feature = "ff")]
pub use f2e19x3e26::F2e19x3e26;

pub mod polynomial;

pub mod fft;
