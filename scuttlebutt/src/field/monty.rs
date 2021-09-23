//! Generic 64-bit Montgomery arithmetic for prime fields.

use generic_array::{GenericArray, typenum};
use rand::distributions::{Distribution, Uniform};
use std::fmt::Debug;
use std::hash::Hash;
use subtle::ConstantTimeEq;

use crate::field::BiggerThanModulus;

#[cfg(test)]
use proptest::{*, prelude::*};

/* Based on https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
 * and https://github.com/snipsco/rust-threshold-secret-sharing
 */

/* Constants for Montgomery conversion/reduction.
 *
 * Need:
 *      R*R_INV - M*M_TICK = 1
 * Given:
 *      R = 2^64
 *      M is the field modulus
 */

/// R value for 64-bit Montgomery numbers: 2^64.
pub const R: u128 = 1<<64;

/// Provides 64-bit Montgomery arithmetic for a struct given
///     * The desired field modulus M
///     * M_TICK = 2^64 - (M^-1 mod R)
///     * R_INV = 2^-64 mod M
///     * to_raw(): A constructor for the underlying u64 value
///     * from_raw(): A destructor for the underlying u64 value
///
/// The following constant is provided with default implementations (and the
/// default should not be overridden if you want the Montgomery arithmetic to
/// work):
///     * R_CUBE = (2^64)^3
//
// TODO: Can we give M_TICK, R_INV, and BITS default implementations, so an
// impl only needs to specify the modulus, generator, setter, and getter?
// They are uniquely determined by M, but modular inversion and determining
// bit-width seem difficult to do statically.
pub trait Monty: 'static + Send + Sync + Sized + Copy + Clone + Default + Hash + Debug {
    /// Desired field modulus
    const M: u64;       // Field modulus

    /// `M' = 2^64 - (M^-1 mod 2^64)`
    const M_TICK: u64;  // R - (M^-1 mod R)

    /// `(2^64)^-1 mod M`
    const R_INV: u64;   // R^-1 mod M

    /// `(2^64)^3 mod M`
    ///
    /// Note: You probably don't want to implement this
    const R_CUBE: u64 = // R^3 mod M
        (((((R % Self::M as u128)
            * R) % Self::M as u128)
                * R) % Self::M as u128) as u64;
    
    /// Generator of the multiplicative field mod `M`, i.e., `G^phi(M) = 1`
    const G: Self;

    /// Bitwidth of the field modulus, i.e., least `k` s.t. `M < 2^k`
    const BITS: usize;

    /// Constructor for the field struct from raw u64 Montgomery form
    fn to_raw(&self) -> u64;

    /// Destructor from the field struct to raw u64 Montgomery form
    fn from_raw(other: u64) -> Self;

    /// Raw u64 Montgomery representation of 0
    ///
    /// Note: You probably don't want to implement this
    const RAW_ZERO: u64 = 0;

    /// Raw u64 Montgomery representation of 1
    ///
    /// Note: You probably don't want to implement this
    const RAW_ONE: u64 = (R % Self::M as u128) as u64;
}

/// Convert a u128 into a field element in Montgomery form into using one
/// division
#[inline]
pub fn monty_from_u128<F: Monty>(a: u128) -> F {
    F::from_raw(((a << 64) % F::M as u128) as u64)
}

/// Convert a literal that can be cast to u128 into Montgomery form statically
#[macro_export]
macro_rules! monty_from_lit {
    ($n: literal, $modulus: path) => {
        ((($n as u128) << 64) % $modulus as u128) as u64
    }
}

/// Convert a field element in Montgomery form into a u128 using one division
#[inline]
pub fn monty_to_u128<F: Monty>(u: F) -> u128 {
    (u.to_raw() as u128 * (F::R_INV as u128)) % F::M as u128
}

/* Operations
 */

// Montgomery reduction:
// https://en.wikipedia.org/wiki/Montgomery_modular_multiplication#The_REDC_algorithm
//
// Given:  a in unreduced raw Montgomery form
//         m the field modulus
//         m' s.t. m' = 2^64 - (m^-1 mod 2^64)
// Return: a*(2^64)-1 mod m in reduced Montgomery form
#[inline]
fn redc(a: u128, modulus: u64, m_tick: u64) -> u128 {
    let m = (a as u64).wrapping_mul(m_tick) as u128;
    let t = ((a + m*(modulus as u128)) >> 64) as u64;

    // At this point we know that t < 2*modulus
    ct_reduce(t as u128, modulus) as u128
}

// Modular reduction for integers in [0, 2*modulus), a la Algoritm 1 of
// https://eprint.iacr.org/2017/437.pdf
//
// Require: a < 2*modulus
#[inline]
fn ct_reduce(a: u128, modulus: u64) -> u64 {
    // mask in {0,1}^64 is 1^64 if a >= modulus or 0^64 o.w.
    let mask = ((a < modulus as u128) as u128).wrapping_sub(1);
    let diff = a.wrapping_sub(modulus as u128);

    (a ^ (mask & (a ^ diff))) as u64
}

/// Addition for field elements in Montgomery form
#[inline]
pub fn monty_add<F: Monty>(a: F, b: F) -> F {
    let ab = a.to_raw() as u128 + b.to_raw() as u128;

    F::from_raw(ct_reduce(ab, F::M))
}

/// Subtraction for field elements in Montgomery form
#[inline]
pub fn monty_sub<F: Monty>(a: F, b: F) -> F { monty_add(a, monty_neg(b)) }

/// Additive inverse for field elements in Montgomery form
#[inline]
pub fn monty_neg<F: Monty>(a: F) -> F { F::from_raw(F::M - a.to_raw()) }

/// Multiplication for field elements in Montgomery form
#[inline]
pub fn monty_mul<F: Monty>(a: F, b: F) -> F {
    let ab = (a.to_raw() as u128).wrapping_mul(b.to_raw() as u128);

    F::from_raw(redc(ab, F::M, F::M_TICK) as u64)
}

/// Division for field elements in Montgomery form
#[inline]
pub fn monty_div<F: Monty>(a: F, b: F) -> F { monty_mul(a, monty_inv(b)) }

/// Multiplicative inverse for field elements in Montgomery form
#[inline]
pub fn monty_inv<F: Monty>(a: F) -> F {
    if a.to_raw() == 0 { panic!("Division by zero") }

    let a_inv = gcd(a.to_raw() as i128, F::M as i128).0 as u128;

    F::from_raw(redc(a_inv.wrapping_mul(F::R_CUBE as u128), F::M, F::M_TICK) as u64)
}

/// Equality for field elements in Montgomery form
#[inline]
pub fn monty_eq<F: Monty>(a: F, b: F) -> bool {
    a.to_raw() == b.to_raw()
}

/// Equality for field elements in Montgomery form in constant time
#[inline]
pub fn monty_ct_eq<F: Monty>(a: F, b: F) -> subtle::Choice {
    a.to_raw().ct_eq(&b.to_raw())
}

/// Convert a field element in Montgomery form to a byte array
pub fn monty_to_bytes<F: Monty>(&f: &F) -> GenericArray<u8, typenum::U8> {
    GenericArray::from((monty_to_u128(f) as u64).to_le_bytes())
}

/// Convert a byte array to a field element in Montgomery form
pub fn monty_from_bytes<F: Monty>(
    bs: &GenericArray<u8, typenum::U8>
) -> Result<F, BiggerThanModulus> {
    let n = u64::from_le_bytes(*bs.as_ref());
    if n < F::M { Ok(monty_from_u128(n as u128)) } else { Err(BiggerThanModulus) }
}

/// Convert a random byte array to a field element in Montgomery form
// XXX: Not actually enough entropy. Need 32 bytes.
pub fn monty_from_uniform_bytes<F: Monty>(bytes: &[u8; 16]) -> F {
    use rand::prelude::{StdRng, SeedableRng};

    let mut seed = [0u8; 32];
    for i in 0..16 {
        seed[i] = bytes[i];
    }

    let mut rng = StdRng::from_seed(seed);
    F::from_raw(Uniform::from(0 .. F::M).sample(&mut rng))
}

/// Generate a uniformly random field element
pub fn monty_random<F: Monty, R: rand_core::RngCore + ?Sized>(rng: &mut R) -> F {
    F::from_raw(Uniform::from(0 .. F::M).sample(rng))
}

// Extended GCD based on
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
//
// Given: a, b in Z
// Return: (x, y) s.t.
//      a*x + b*y = g = gcd(a, b)
//      0 <= x < |b/g|
//      -|a/g| < y <= 0
//
// TODO Re-implement based on https://eprint.iacr.org/2020/972.pdf?
#[inline]
fn gcd(a0: i128, b0: i128) -> (i128, i128) {
    let mut a = a0; let mut b = b0;
    let mut p = 1;  let mut q = 0;
    let mut r = 0;  let mut s = 1;

    while b != 0 {
        let t = a / b;
        p -= t * r; std::mem::swap(&mut p, &mut r);
        q -= t * s; std::mem::swap(&mut q, &mut s);
        a -= t * b; std::mem::swap(&mut a, &mut b);
    }

    if a < 0 { p = -p; q = -q; }
    if p < 0 { p += b0/a; q -= a0/a; }

    (p, q)
}

#[test]
fn test_gcd() {
    assert_eq!(gcd(12, 20), (2, -1));
    assert_eq!(gcd(42, 66), (8, -5));
}

/// Implement FiniteField, as well as arithmetic and equality operations, based
/// on Montgomery operations.
///
/// Implements the following traits:
///     * Add
///     * AddAssign
///     * Sub
///     * SubAssign
///     * Mul
///     * MullAssign
///     * Div
///     * DivAssign
///     * Sum
///     * Product
///     * PartialEq
///     * Eq
///     * ConstantTimeEq
///     * ConditionallySelectable
///     * FiniteField
///
/// Assumes the type already implements the following traits:
///     * Monty
#[macro_export]
macro_rules! implement_finite_field_for_monty {
    ($monty: ty) => {
        impl std::ops::Add<$monty> for $monty {
            type Output = $monty;
            #[inline]
            fn add(self, other: $monty) -> Self::Output { $crate::field::monty::monty_add(self, other) }
        }
        impl std::ops::AddAssign<$monty> for $monty {
            #[inline]
            fn add_assign(&mut self, other: $monty) { *self = $crate::field::monty::monty_add(*self, other) }
        }
        impl std::ops::Sub<$monty> for $monty {
            type Output = $monty;
            #[inline]
            fn sub(self, other: $monty) -> Self::Output { $crate::field::monty::monty_sub(self, other) }
        }
        impl std::ops::SubAssign<$monty> for $monty {
            #[inline]
            fn sub_assign(&mut self, other: $monty) { *self = $crate::field::monty::monty_sub(*self, other) }
        }
        impl std::ops::Mul<$monty> for $monty {
            type Output = $monty;
            #[inline]
            fn mul(self, other: $monty) -> Self::Output { $crate::field::monty::monty_mul(self, other) }
        }
        impl std::ops::MulAssign<$monty> for $monty {
            #[inline]
            fn mul_assign(&mut self, other: $monty) { *self = $crate::field::monty::monty_mul(*self, other) }
        }
        impl std::ops::Div<$monty> for $monty {
            type Output = $monty;
            #[inline]
            fn div(self, other: $monty) -> Self::Output { $crate::field::monty::monty_div(self, other) }
        }
        impl std::ops::DivAssign<$monty> for $monty {
            #[inline]
            fn div_assign(&mut self, other: $monty) { *self = $crate::field::monty::monty_div(*self, other) }
        }
        impl std::ops::Neg for $monty {
            type Output = $monty;
            #[inline]
            fn neg(self) -> Self::Output { $crate::field::monty::monty_neg(self) }
        }
        impl std::iter::Sum<$monty> for $monty {
            fn sum<I: Iterator<Item = $monty>>(iter: I) -> $monty {
                iter.fold(<$monty>::from_raw(<$monty>::RAW_ZERO), $crate::field::monty::monty_add)
            }
        }
        impl std::iter::Product<$monty> for $monty {
            fn product<I: Iterator<Item = $monty>>(iter: I) -> $monty {
                iter.fold(<$monty>::from_raw(<$monty>::RAW_ONE), $crate::field::monty::monty_mul)
            }
        }
        impl PartialEq for $monty {
            #[inline]
            fn eq(&self, other: &$monty) -> bool { $crate::field::monty::monty_eq(*self, *other) }
        }
        impl Eq for $monty {}
        impl subtle::ConstantTimeEq for $monty {
            #[inline]
            fn ct_eq(&self, other: &$monty) -> subtle::Choice { $crate::field::monty::monty_ct_eq(*self, *other) }
        }
        impl subtle::ConditionallySelectable for $monty {
            #[inline]
            fn conditional_select(a: &$monty, b: &$monty, c: subtle::Choice) -> Self {
                <$monty>::from_raw(u64::conditional_select(&a.to_raw(), &b.to_raw(), c))
            }
        }
        impl $crate::field::PrimeFiniteField for $monty {
            // XXX: Maybe not the most efficient way to do this? Uses a single division operation
            // in monty_to_u128.
            fn mod2(&self) -> Self {
                if monty_to_u128(*self) & 0x1 == 0 {
                    Self(monty_from_lit!(0, Self::M))
                } else {
                    Self(monty_from_lit!(1, Self::M))
                }
            }
        }
        impl $crate::field::FiniteField for $monty {
            const ZERO: Self = Self(monty_from_lit!(0, Self::M));
            const ONE: Self = Self(monty_from_lit!(1, Self::M));
            const MODULUS: u128 = Self::M as u128;
            const GENERATOR: Self = Self(7);
            const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS - 1;

            type ByteReprLen = generic_array::typenum::U8;
            type FromBytesError = $crate::field::BiggerThanModulus;

            fn to_bytes(&self) -> $crate::field::GenericArray<u8, Self::ByteReprLen> {
                $crate::field::monty::monty_to_bytes(self)
            }

            fn from_bytes(
                bytes: &$crate::field::GenericArray<u8, Self::ByteReprLen>
            ) -> Result<Self, Self::FromBytesError> {
                $crate::field::monty::monty_from_bytes(bytes)
            }

            fn from_uniform_bytes(bytes: &[u8; 16]) -> Self {
                $crate::field::monty::monty_from_uniform_bytes(bytes)
            }

            fn random<R: rand_core::RngCore + ?Sized>(rng: &mut R) -> Self {
                $crate::field::monty::monty_random(rng)
            }

            type PrimeField = Self;
            type PolynomialFormNumCoefficients = generic_array::typenum::U1;

            fn from_polynomial_coefficients(
                coeffs: generic_array::GenericArray<
                    Self::PrimeField,
                    Self::PolynomialFormNumCoefficients,
                >
            ) -> Self {
                coeffs[0]
            }

            fn to_polynomial_coefficients(
                &self
            ) -> generic_array::GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
                generic_array::GenericArray::from([*self])
            }

            fn reduce_multiplication_over() -> $crate::field::Polynomial<Self::PrimeField> {
                $crate::field::Polynomial::x()
            }

            fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
                *self * pf
            }

            #[inline]
            fn inverse(&self) -> Self { $crate::field::monty::monty_inv(*self) }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Copy, Clone, Default, Hash)]
    struct F11(u64);

    impl std::fmt::Debug for F11 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_fmt(format_args!(
                "[F({}) = {}]",
                self.0,
                (self.0 as u128 * (Self::R_INV as u128)) % Self::M as u128,
            ))
        }
    }

    impl Monty for F11 {
        const M: u64 = 11;
        const M_TICK: u64 = ((2u128<<64) - 3_353_953_467_947_191_203u128) as u64;
        const R_INV: u64 = 9;

        const G: Self = Self(monty_from_lit!(2, Self::M));
        const BITS: usize = 4;

        #[inline]
        fn to_raw(&self) -> u64 { self.0 }

        #[inline]
        fn from_raw(raw: u64) -> Self { Self(raw) }
    }

    impl std::convert::From<u128> for F11 {
        #[inline]
        fn from(n: u128) -> Self { monty_from_u128(n) }
    }

    implement_finite_field_for_monty!{F11}

    test_field!(test_f11, F11);

    #[test]
    fn test_f11_add() {
        assert_eq!(F11::from(5) + F11::from(7), F11(F11::RAW_ONE))
    }
}
