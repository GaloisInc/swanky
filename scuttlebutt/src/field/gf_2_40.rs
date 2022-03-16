use crate::field::{f2::F2, polynomial::Polynomial, BiggerThanModulus, FiniteField, IsSubfieldOf};
use generic_array::GenericArray;
use rand_core::RngCore;
use smallvec::smallvec;
use std::{
    convert::TryFrom,
    iter::FromIterator,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use vectoreyes::{SimdBase, U64x2};

/// An element of the finite field $`\textsf{GF}(2^{40})`$ reduced over $`x^{40} + x^5 + x^4 + x^3 + 1`$
#[derive(Debug, Clone, Copy, Hash, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct Gf40(u64);

impl Gf40 {
    /// Extract the raw bits of this field element as a `u64`.
    ///
    /// Only the lower 40 bits may be set.
    #[inline(always)]
    pub fn extract_raw(&self) -> u64 {
        debug_assert_eq!(self.0 >> 40, 0);
        self.0
    }

    /// Construct a field element using the lower 40 bits of the input word.
    #[inline(always)]
    pub fn from_lower_40(x: u64) -> Self {
        Gf40(x & ((1 << 40) - 1))
    }
}

impl ConstantTimeEq for Gf40 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for Gf40 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf40(u64::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a Gf40> for Gf40 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a Gf40) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a Gf40> for Gf40 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a Gf40) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}

impl<'a> MulAssign<&'a Gf40> for Gf40 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a Gf40) {
        let (r_lower, the_upper) = {
            let product = U64x2::set_lo(self.0).carryless_mul::<false, false>(U64x2::set_lo(rhs.0));
            (product.extract::<0>(), product.extract::<1>())
        };

        // Now we reduce the wide product.
        // This reduction algorithm is a translation of C++ code written by Daniel Kales
        let upper_mask: u64 = 0xffff;
        let lower_mask: u64 = 0xFFFFFFFFFF;

        let t = ((the_upper & upper_mask) << 24) | (r_lower >> 40);
        let r_upper = t ^ (t >> 35) ^ (t >> 36) ^ (t >> 37);
        let r_lower = r_lower ^ (r_upper << 5) ^ (r_upper << 4) ^ (r_upper << 3) ^ (r_upper << 0);
        self.0 = lower_mask & r_lower;
    }
}

impl FiniteField for Gf40 {
    type ByteReprLen = generic_array::typenum::U5;
    type FromBytesError = BiggerThanModulus;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        let mut buf = [0; 8];
        buf[0..5].copy_from_slice(bytes);
        let raw = u64::from_le_bytes(buf);
        if raw < (1 << 40) {
            Ok(Gf40(raw))
        } else {
            Err(BiggerThanModulus)
        }
    }

    #[inline]
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        GenericArray::from_slice(&self.0.to_le_bytes()[0..5]).clone()
    }

    type PrimeField = F2;
    type PolynomialFormNumCoefficients = generic_array::typenum::U40;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        let mut out = 0;
        for x in coeff.iter().rev() {
            out <<= 1;
            out |= u64::from(u8::from(*x));
        }
        Gf40(out)
    }

    #[inline]
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Gf40((u128::from_le_bytes(*x) & ((1 << 40) - 1)) as u64)
    }

    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        let x = self.0;
        GenericArray::from_iter(
            (0..40).map(|shift| F2::try_from(((x >> shift) & 1) as u8).unwrap()),
        )
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        // x^40 + x^5 + x^4 + x^3 + 1
        let mut coefficients = smallvec![F2::ZERO; 128];
        coefficients[40 - 1] = F2::ONE;
        coefficients[5 - 1] = F2::ONE;
        coefficients[4 - 1] = F2::ONE;
        coefficients[3 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }

    #[inline]
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        Gf40(rng.next_u64() & ((1 << 40) - 1))
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U40;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        super::standard_bit_decomposition(u128::from(self.0))
    }

    // This corresponds to the polynomial P(x) = x
    const GENERATOR: Self = Gf40(2);

    const ZERO: Self = Gf40(0);

    const ONE: Self = Gf40(1);

    #[inline]
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        // Equivalent to:
        // Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
        Gf40((!((pf.0 as u64).wrapping_sub(1))) & self.0)
    }

    #[inline]
    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_limit((1 << 40) - 2, 40)
    }
}

impl IsSubfieldOf<Gf40> for F2 {
    fn lift_into_superfield(&self) -> Gf40 {
        debug_assert!(self.0 <= 1);
        Gf40(self.0 as u64)
    }
}

field_ops!(Gf40);

#[cfg(test)]
test_field!(test_gf40, Gf40);
