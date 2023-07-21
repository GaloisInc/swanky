//! This module defines finite fields.

use crate::{
    polynomial::Polynomial,
    ring::{FiniteRing, IsSubRingOf},
};
use crypto_bigint::{Limb, Uint};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use std::ops::{Div, DivAssign};
use subtle::CtOption;
use swanky_generic_array::AnyArrayLength;

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
    type NumberOfBitsInBitDecomposition: ArrayLength<bool> + AnyArrayLength;
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
    fn decompose<T: FiniteField + IsSubFieldOf<Self>>(
        &self,
    ) -> GenericArray<T, DegreeModulo<T, Self>> {
        T::decompose_superfield(self)
    }
    /// Create a field element from an array of subfield `T` elements.
    ///
    /// See [`IsSubFieldOf`] for more info.
    #[inline]
    fn from_subfield<T: FiniteField + IsSubFieldOf<Self>>(
        arr: &GenericArray<T, DegreeModulo<T, Self>>,
    ) -> Self {
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
///
/// This trait provides methods to convert to and from the the [`Uint`] type
/// from the [`crypto_bigint`] crate. These are large integers, parameterized
/// over the number of limbs (i.e. machine words) used in their representation.
///
/// The conversion methods are generic over the number of limbs for caller's
/// convenience. The constant `MIN_LIMBS_NEEDED` is a number of limbs large
/// enough to store the modulus of the `PrimeFiniteField`.
///
/// All of the methods provided by this trait should run in constant time.
pub trait PrimeFiniteField:
    FiniteField<PrimeField = Self>
    + IsSubFieldOf<Self, DegreeModulo = generic_array::typenum::U1>
    + std::convert::TryFrom<u128>
{
    /// The minimum number of word-sized limbs needed to represent the modulus
    /// of the `PrimeFiniteField`.
    const MIN_LIMBS_NEEDED: usize =
        (Self::NumberOfBitsInBitDecomposition::USIZE + Limb::BITS - 1) / Limb::BITS;

    /// Return the modulus of this `PrimeFiniteField` as a `Uint`.
    ///
    /// # Panics
    ///
    /// This method should panic if `LIMBS` < `MIN_LIMBS_NEEDED`.
    fn modulus_int<const LIMBS: usize>() -> Uint<LIMBS>;

    /// Convert a `PrimeFiniteField` value into a `Uint`.
    ///
    /// # Panics
    ///
    /// This method should panic if `LIMBS` < `MIN_LIMBS_NEEDED`.
    fn into_int<const LIMBS: usize>(&self) -> Uint<LIMBS>;

    /// Try to convert a `Uint` into a `PrimeFiniteField` value, returning
    /// a [`CtOption`].
    fn try_from_int<const LIMBS: usize>(x: Uint<LIMBS>) -> CtOption<Self>;
}

/// Automatically implement boilerplate field operations for the given type.
///
/// This macro is used like `field_ops!(my_type)`. If `my_type` already has a [`std::iter::Sum`]
/// implementation, this macro can be asked to not generate an implementation of `Sum` via
/// `field_ops!(my_type, SUM_ALREADY_DEFINED)`.
#[macro_export]
macro_rules! field_ops {
    ($f:ident $($tt:tt)*) => {
        $crate::ring_ops!($f $($tt)*);

        $crate::ring_ops!(@binop Div, div, std::ops::DivAssign::div_assign, $f);
        $crate::ring_ops!(@assign_op DivAssign, div_assign, $f);

        impl<'a> std::ops::DivAssign<&'a $f> for $f {
            fn div_assign(&mut self, rhs: &Self) {
                *self *= rhs.inverse();
            }
        }
    };
}

/// Bit decomposition of `bits` into an array.
pub fn standard_bit_decomposition<L: ArrayLength<bool>>(bits: u128) -> GenericArray<bool, L> {
    let mut out: GenericArray<bool, L> = Default::default();
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = (bits & (1 << (i as u128))) != 0;
    }
    out
}
