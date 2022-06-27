use super::{BiggerThanModulus, FiniteField, IsSubfieldOf, Polynomial, F2};
use bytemuck::{TransparentWrapper, Zeroable};
use generic_array::{typenum::Unsigned, GenericArray};
use rand::RngCore;
use smallvec::smallvec;
use std::iter::FromIterator;
use std::ops::{AddAssign, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    SimdBase, U64x2,
};

/// A GF(2) extension field such that:
/// 1. `Self` is `repr(transparent)` to a `u64`
/// 2. `Self` consists of 63 or fewer bits that are stored in the lower bits of the `u64`.
/// 3. The upper bits of the `u64` are zero.
/// # Safety
/// All the requirements above _must_ be met when this trait is `unsafe impl`'d.
///
/// Note that types which implement `SmallBinaryField`, do not need to (and probably should not)
/// implement [`bytemuck::Pod`]. This type _wraps_ a POD `u64`, but this type has additional
/// requirements on its set of values, compared to a `u64`.
pub unsafe trait SmallBinaryField:
    FiniteField<PrimeField = F2> + TransparentWrapper<u64> + Zeroable
{
    /// Produce a field element of `Self` by zeroing the upper bits of `x`.
    fn from_lower_bits(x: u64) -> Self {
        let out = x & (1 << Self::PolynomialFormNumCoefficients::U64) - 1;
        debug_assert_eq!((out >> Self::PolynomialFormNumCoefficients::U64), 0);
        Self::wrap(out)
    }
    /// Reduce the result of a single 128-bit carryless multiply of two `Self` values modulo
    /// [`FiniteField::reduce_multiplication_over()`]
    fn reduce(x: U64x2) -> Self;
    /// Reduce the result of several 128-bit carryless multiply operations over
    /// [`FiniteField::reduce_multiplication_over()`].
    #[inline(always)]
    fn reduce_vectored<const N: usize>(uppers: [U64x2; N], lowers: [U64x2; N]) -> [U64x2; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        uppers.array_zip(lowers).array_map(
            #[inline(always)]
            |(uppers, lowers)| {
                let a = lowers.unpack_lo(uppers);
                let b = lowers.unpack_hi(uppers);
                U64x2::from([Self::peel(Self::reduce(a)), Self::peel(Self::reduce(b))])
            },
        )
    }
}

macro_rules! small_binary_field {
    (
        $(#[$m:meta])*
        $name:ident, $mod_name:ident,
        num_bits = $num_bits:ty,
        polynomial_modulus = $modulus_fn:ident,
        reduce = $reduce_fn:ident,
        $(reduce_vectored = $reduce_vectored_fn:ident)?
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, Hash, Eq, bytemuck::Zeroable, TransparentWrapper)]
        #[repr(transparent)]
        pub struct $name(u64);
        field_ops!($name);
        impl ConstantTimeEq for $name {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }
        impl ConditionallySelectable for $name {
            #[inline]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self(u64::conditional_select(&a.0, &b.0, choice))
            }
        }

        impl<'a> AddAssign<&'a $name> for $name {
            #[inline]
            fn add_assign(&mut self, rhs: &'a $name) {
                self.0 ^= rhs.0;
            }
        }
        impl<'a> SubAssign<&'a $name> for $name {
            #[inline]
            fn sub_assign(&mut self, rhs: &'a $name) {
                // The additive inverse of GF(2^128) is the identity
                *self += rhs;
            }
        }

        impl<'a> MulAssign<&'a $name> for $name {
            #[inline]
            fn mul_assign(&mut self, rhs: &'a $name) {
                let product = U64x2::set_lo(self.0).carryless_mul::<false, false>(U64x2::set_lo(rhs.0));
                // Now we reduce the wide product.
                *self = Self::reduce(product);
            }
        }

        impl FiniteField for $name {
            type Serializer = crate::field::serialization::ByteFiniteFieldSerializer<Self>;
            type Deserializer = crate::field::serialization::ByteFiniteFieldDeserializer<Self>;
            // ceil($num_bits / 8) = ($num_bits + 8 - 1) / 8 = ($num_bits + 7) / 8
            type ByteReprLen = <
                <generic_array::typenum::U7 as std::ops::Add<$num_bits>>::Output as
                std::ops::Div<generic_array::typenum::U8>
            >::Output;
            type FromBytesError = BiggerThanModulus;

            #[inline]
            fn from_bytes(
                bytes: &GenericArray<u8, Self::ByteReprLen>,
            ) -> Result<Self, Self::FromBytesError> {
                let mut buf = [0; 8];
                buf[0..Self::ByteReprLen::USIZE].copy_from_slice(&bytes);
                let raw = u64::from_le_bytes(buf);
                if (raw >> <$num_bits as Unsigned>::U64) == 0 {
                    Ok($name(raw))
                } else {
                    Err(BiggerThanModulus)
                }
            }

            #[inline]
            fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
                #[cfg(debug_assertions)]
                {
                    for x in self.0.to_le_bytes()[Self::ByteReprLen::USIZE..].iter().copied() {
                        debug_assert_eq!(x, 0);
                    }
                }
                GenericArray::from_slice(&self.0.to_le_bytes()[0..Self::ByteReprLen::USIZE]).clone()
            }

            type PrimeField = F2;
            type PolynomialFormNumCoefficients = $num_bits;

            fn from_polynomial_coefficients(
                coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
            ) -> Self {
                let mut out = 0;
                for x in coeff.iter().rev() {
                    out <<= 1;
                    out |= u64::from(u8::from(*x));
                }
                $name(out)
            }

            #[inline]
            fn from_uniform_bytes(x: &[u8; 16]) -> Self {
                Self::from_lower_bits(u128::from_le_bytes(*x) as u64)
            }

            fn to_polynomial_coefficients(
                &self,
            ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
                let x = self.0;
                GenericArray::from_iter(
                    (0..<$num_bits as Unsigned>::U64).map(
                        |shift| F2::try_from(((x >> shift) & 1) as u8).unwrap()
                    ),
                )
            }

            fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
                $modulus_fn()
            }

            #[inline]
            fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
                Self::from_lower_bits(rng.next_u64())
            }

            type NumberOfBitsInBitDecomposition = $num_bits;

            fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
                super::standard_bit_decomposition(u128::from(self.0))
            }

            // This corresponds to the polynomial P(x) = x
            const GENERATOR: Self = $name(0b10);

            const ZERO: Self = $name(0);

            const ONE: Self = $name(1);

            #[inline]
            fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
                // Equivalent to:
                // Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
                let new = (!((pf.0 as u64).wrapping_sub(1))) & self.0;
                debug_assert!(new == 0 || new == self.0);
                Self(new)
            }

            fn inverse(&self) -> Self {
                if *self == Self::ZERO {
                    panic!("Zero cannot be inverted");
                }
                self.pow_var_time((1 << <$num_bits as Unsigned>::U64) - 2)
            }
        }
        impl IsSubfieldOf<$name> for F2 {
            fn multiply_by_superfield(&self, x: $name) -> $name {
                x.multiply_by_prime_subfield(*self)
            }
            fn lift_into_superfield(&self) -> $name {
                debug_assert!(self.0 <= 1);
                $name(self.0 as u64)
            }
        }

        impl $name {
            const NUM_BITS_OF_WIDEST_PRODUCT: u64 = <$num_bits as Unsigned>::U64 * 2 - 1;
        }

        unsafe impl SmallBinaryField for $name {
            #[inline(always)] // due to SIMD
            fn reduce(product: U64x2) -> Self {
                debug_assert!($name::NUM_BITS_OF_WIDEST_PRODUCT >= 64);
                debug_assert_eq!(product.extract::<1>() >> ($name::NUM_BITS_OF_WIDEST_PRODUCT - 64), 0);
                $reduce_fn(product)
            }

            $(#[inline(always)] // due to SIMD
            fn reduce_vectored<const N: usize>(uppers: [U64x2; N], lowers: [U64x2; N]) -> [U64x2; N]
            where
                ArrayUnrolledOps: UnrollableArraySize<N>,
            {
                debug_assert!($name::NUM_BITS_OF_WIDEST_PRODUCT >= 64);
                #[cfg(debug_assertions)]
                {
                    for upper in uppers.iter()
                        .copied()
                        .flat_map(|x| IntoIterator::into_iter(x.as_array()))
                    {
                        debug_assert_eq!(upper >> ($name::NUM_BITS_OF_WIDEST_PRODUCT - 64), 0);
                    }
                }
                $reduce_vectored_fn::<N>(uppers, lowers)
            })?
        }

        #[cfg(test)]
        mod $mod_name {
            use super::*;
            use proptest::prelude::*;
            #[test]
            fn small_enough() {
                assert!(<$num_bits as Unsigned>::U64 <= 63);
            }
            proptest! {
                #[test]
                fn test_vectorized_reduction(
                    a in 0..(1_u128 << $name::NUM_BITS_OF_WIDEST_PRODUCT),
                    b in (0..(1_u128 << $name::NUM_BITS_OF_WIDEST_PRODUCT))
                ) {
                    let a: U64x2 = bytemuck::cast(a);
                    let b: U64x2 = bytemuck::cast(b);
                    let lowers = a.unpack_lo(b);
                    let uppers = a.unpack_hi(b);
                    let [a_reduced, b_reduced] = $name::reduce_vectored([uppers], [lowers])[0].as_array();
                    prop_assert_eq!(a_reduced, $name::reduce(a).0);
                    prop_assert_eq!(b_reduced, $name::reduce(b).0);
                }
            }
            test_field!(test_field, $name);
        }
    };
}

#[inline(always)] // due to SIMD
fn reduce_f63b(product: U64x2) -> F63b {
    let [lower, upper] = product.as_array();
    let reduced = lower ^ (lower >> 63) ^ (upper << 1) ^ ((lower >> 62) & 0b10) ^ (upper << 2);
    F63b::from_lower_bits(reduced)
}

#[inline(always)] // due to SIMD
fn reduce_vectored_f63b<const N: usize>(uppers: [U64x2; N], lowers: [U64x2; N]) -> [U64x2; N]
where
    ArrayUnrolledOps: UnrollableArraySize<N>,
{
    // Since all of our operations have 1 cycle of latency, it's cheaper (in terms of registers)
    // to not interleave any of these operations.
    uppers.array_zip(lowers).array_map(
        #[inline(always)]
        |(uppers, lowers)| {
            let shr_63 = lowers.shift_right::<63>();
            let unmasked = lowers
                ^ shr_63
                ^ uppers.shift_left::<1>()
                ^ shr_63.shift_left::<1>()
                ^ uppers.shift_left::<2>();
            unmasked.shift_left::<1>().shift_right::<1>()
        },
    )
}

fn polynomial_modulus_f63b() -> Polynomial<F2> {
    let mut coefficients = smallvec![F2::ZERO; 63];
    coefficients[63 - 1] = F2::ONE;
    coefficients[1 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

small_binary_field!(
    /// An element of the finite field $`\textsf{GF}(2^{63})`$ reduced over $`x^{63} + x + 1`$
    F63b,
    f63b,
    num_bits = generic_array::typenum::U63,
    polynomial_modulus = polynomial_modulus_f63b,
    reduce = reduce_f63b,
    reduce_vectored = reduce_vectored_f63b
);

#[inline(always)] // due to SIMD
fn reduce_f56b(product: U64x2) -> F56b {
    // TODO: implement this more efficiently
    let x: u128 = bytemuck::cast(product);
    let reduced = ((x >> 0) & 0b0000000011111111111111111111111111111111111111111111111111111111
        ^ (x >> 48) & 0b0000000011111111111111111111111111111111111111111111111100000000
        ^ (x >> 53) & 0b0000011111111111111111111111111111111111111111111111111111000
        ^ (x >> 54) & 0b000011111111111111111111111111111111111111111111111111111100
        ^ (x >> 56) & 0b0011111111111111111111111111111111111111111111111111111111
        ^ (x >> 96) & 0b111111111100000000
        ^ (x >> 101) & 0b0000011111000
        ^ (x >> 102) & 0b000011111100
        ^ (x >> 104) & 0b0011111111
        ^ (x >> 106) & 0b11111000
        ^ (x >> 107) & 0b0000100
        ^ (x >> 108) & 0b111100
        ^ (x >> 109) & 0b00111
        ^ (x >> 110) & 0b0011
        ^ (x >> 112) & 0b11) as u64;
    debug_assert_eq!(reduced >> 56, 0);
    F56b(reduced)
}

fn polynomial_modulus_f56b() -> Polynomial<F2> {
    let mut coefficients = smallvec![F2::ZERO; 56];
    coefficients[56 - 1] = F2::ONE;
    coefficients[8 - 1] = F2::ONE;
    coefficients[3 - 1] = F2::ONE;
    coefficients[2 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

small_binary_field!(
    /// An element of the finite field $`\textsf{GF}(2^{63})`$ reduced over $`x^{63} + x + 1`$
    F56b,
    f56b,
    num_bits = generic_array::typenum::U56,
    polynomial_modulus = polynomial_modulus_f56b,
    reduce = reduce_f56b,
);

#[inline(always)] // due to SIMD
fn reduce_f40b(product: U64x2) -> F40b {
    let (r_lower, the_upper) = (product.extract::<0>(), product.extract::<1>());
    // This reduction algorithm is a translation of C++ code written by Daniel Kales
    let upper_mask: u64 = 0xffff;
    let lower_mask: u64 = 0xFFFFFFFFFF;

    let t = ((the_upper & upper_mask) << 24) | (r_lower >> 40);
    let r_upper = t ^ (t >> 35) ^ (t >> 36) ^ (t >> 37);
    let r_lower = r_lower ^ (r_upper << 5) ^ (r_upper << 4) ^ (r_upper << 3) ^ (r_upper << 0);
    F40b(lower_mask & r_lower)
}

fn polynomial_modulus_f40b() -> Polynomial<F2> {
    // x^40 + x^5 + x^4 + x^3 + 1
    let mut coefficients = smallvec![F2::ZERO; 40];
    coefficients[40 - 1] = F2::ONE;
    coefficients[5 - 1] = F2::ONE;
    coefficients[4 - 1] = F2::ONE;
    coefficients[3 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

small_binary_field!(
    /// An element of the finite field $`\textsf{GF}(2^{40})`$ reduced over $`x^{40} + x^5 + x^4 + x^3 + 1`$
    F40b,
    f40b,
    num_bits = generic_array::typenum::U40,
    polynomial_modulus = polynomial_modulus_f40b,
    reduce = reduce_f40b,
);

#[inline(always)] // due to SIMD
fn reduce_f45b(wide_product: U64x2) -> F45b {
    let wide_product: u128 = bytemuck::cast(wide_product);
    F45b(
        ((wide_product >> 0) & 0b0000000000000000000111111111111111111111111111111111111111111111
            ^ (wide_product >> 17)
                & 0b0000000000000000000111111111111111110000000000000000000000000000
            ^ (wide_product >> 28)
                & 0b0000000000000000000111111111111111111111111111100000000000000000
            ^ (wide_product >> 34) & 0b0000000000000000000000000000001111111111111111100000000000
            ^ (wide_product >> 45) & 0b00111111111111111110000000000011111111111111111
            ^ (wide_product >> 51) & 0b11111111111111111111111111111100000000000
            ^ (wide_product >> 56) & 0b111111111111111111100000000000000000
            ^ (wide_product >> 62) & 0b110000000000000000011111111111
            ^ (wide_product >> 73) & 0b0011111111111111111
            ^ (wide_product >> 79) & 0b1100000000000
            ^ (wide_product >> 90) & 0b11) as u64,
    )
}

fn polynomial_modulus_f45b() -> Polynomial<F2> {
    //X2^45 + X2^28 + X2^17 + X2^11 + 1
    let mut coefficients = smallvec![F2::ZERO; 128];
    coefficients[45 - 1] = F2::ONE;
    coefficients[28 - 1] = F2::ONE;
    coefficients[17 - 1] = F2::ONE;
    coefficients[11 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

small_binary_field!(
    /// An element of the finite field $\textsf{GF}(2^{45})$ reduced over $x^{45} + x^{28} + x^{17} + x^{11} + 1$
    F45b,
    f45b,
    num_bits = generic_array::typenum::U45,
    polynomial_modulus = polynomial_modulus_f45b,
    reduce = reduce_f45b,
);
