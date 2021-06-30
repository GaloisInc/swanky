use generic_array::{GenericArray, typenum};
use rand::distributions::{Distribution, Uniform, Standard};
use scuttlebutt::field::polynomial::Polynomial;
use scuttlebutt::field::{FiniteField, BiggerThanModulus};
use std::hash::Hash;
use subtle::{ConditionallySelectable, ConstantTimeEq, Choice};

#[cfg(test)]
use proptest::{*, prelude::{Arbitrary, BoxedStrategy, any, Strategy}};

use crate::numtheory::{FieldForFFT2, FieldForFFT3};
use crate::ligero::FieldForLigero;

#[derive(Clone, Copy, Default, Hash)]
pub struct F(u64);

impl FieldForLigero for F {
    const BITS: usize = 61; // floor(log2(Self::MODULUS))
}

impl FiniteField for F {
    const ZERO: Self = F(ZERO_MONTY);
    const ONE: Self = F(ONE_MONTY);
    const MODULUS: u128 = M as u128;
    const GENERATOR: Self = Self(7);
    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS - 1;

    type ByteReprLen = typenum::U8;
    type FromBytesError = BiggerThanModulus;

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        GenericArray::from(self.0.to_le_bytes())
    }

    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>
    ) -> Result<Self, Self::FromBytesError> {
        let n = u64::from_le_bytes(*bytes.as_ref());
        if n < Self::MODULUS as u64 {
            Ok(Self(n))
        } else {
            Err(BiggerThanModulus)
        }
    }

    // TODO: Determine bias
    fn from_uniform_bytes(bytes: &[u8; 16]) -> Self {
        use std::convert::TryFrom;

        let r = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap());
        let mask = (1u64 << Self::BITS) - 1;
        let n = r & mask;
        Self::from(u64::conditional_select(
                &n,
                &(Self::MODULUS as u64 - n),
                Choice::from((n < Self::MODULUS as u64) as u8),
            ))
    }

    fn random<R: rand_core::RngCore + ?Sized>(rng: &mut R) -> Self {
        Self::from(Uniform::from(0 .. Self::MODULUS).sample(rng))
    }

    type PrimeField = Self;
    type PolynomialFormNumCoefficients = typenum::U1;

    fn from_polynomial_coefficients(
        coeffs: GenericArray<
            Self::PrimeField,
            Self::PolynomialFormNumCoefficients,
        >
    ) -> Self {
        coeffs[0]
    }

    fn to_polynomial_coefficients(
        &self
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        GenericArray::from([*self])
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        *self * pf
    }

    // XXX: This is slow. Use GCD. Probably not on a hot path, though.
    #[inline]
    fn inverse(&self) -> Self {
        Self(inv_monty(self.0))
    }

    fn pow(&self, mut e: u128) -> Self {
        let mut b = *self;
        let mut acc = Self::ONE;

        while e != 0 {
            if e & 0b1 == 0b1 {
                acc = b * acc;
            }
            b = b * b;
            e >>= 1;
        }

        acc
    }
}

impl FieldForFFT2 for F {
    const PHI_2_EXP: usize = 19;

    #[inline]
    fn roots_base_2(ix: usize) -> u128 {
        [ 1,                   1332669751402954752, 973258067192839568
        , 1042021548001376395, 402574676512991381,  278717750013534980
        , 74087475420063438,   566374465489511427,  1266925147139716861
        , 855420670760076263,  644012728790649397,  1024672769443274150
        , 969915203910377054,  938399742097549903,  677395270312196759
        , 638309941020567122,  941411658640200634,  214614403681673597
        , 1142590720645869203, 1081812970925941425]
        [ix]
    }
}

impl FieldForFFT3 for F {
    const PHI_3_EXP: usize = 26;

    #[inline]
    fn roots_base_3(ix: usize) -> u128 {
        [ 1,                   460004726804964255, 669043805643439512
        , 296722197659361911,  374719411438346623, 903621615088971058
        , 528204403879753449,  404018507378766984, 569267202400654075
        , 951499245552476893,  869386426445016020, 231629203731078009
        , 911561347291773360,  985928605492343887, 116593309072767134
        , 200952336485094508,  455485850035128309, 567008847283293789
        , 137993045254182336,  158980184853827215, 1203426293655283518
        , 1214402346646813410, 648772824772841070, 1312084489284135569
        , 59416712983923841,   523602121810241645, 920749240289894275]
        [ix]
    }
}

#[cfg(test)]
mod numtheory_tests {
    use super::*;
    use crate::numtheory::*;

    crate::fft2_tests!{F}
    crate::fft3_tests!{F}
    crate::interpolation_tests!{F}
}

impl ConstantTimeEq for F {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // XXX: Probably not actually constant time...
        from_monty(self.0).ct_eq(&from_monty(other.0))
    }
}

impl ConditionallySelectable for F {
    fn conditional_select(a: &Self, b: &Self, c: subtle::Choice) -> Self {
        F(u64::conditional_select(&a.0, &b.0, c))
    }
}

// XXX: This uses an extra division because of the signed representation
// needed by rust_threshold_secret_sharing. Can't see a way around it atm.
impl std::convert::From<i128> for F {
    #[inline]
    fn from (n: i128) -> F {
        let n_mod = n % M as i128;
        let n_pos = if n_mod >= 0 { n_mod } else { M as i128 + n_mod } as u128;

        Self(to_monty(n_pos))
    }
}

impl std::convert::From<F> for i128 {
    #[inline]
    fn from (F(n): F) -> i128 { from_monty(n) as i128 }
}

impl std::convert::From<u128> for F {
    #[inline]
    fn from(n: u128) -> F { Self(to_monty(n)) }
}

impl std::convert::From<F> for u128 {
    #[inline]
    fn from(F(n): F) -> u128 { from_monty(n) }
}

impl std::convert::From<u64> for F {
    #[inline]
    fn from(n: u64) -> F { Self(to_monty(n as u128)) }
}

impl std::convert::From<F> for u64 {
    #[inline]
    fn from(F(n): F) -> u64 { from_monty(n) as u64 }
}

macro_rules! binary_op {
    ($op: ident, $fun: ident, $base_fun: path, $typ: ident) => {
        impl $op<$typ> for $typ {
            type Output = $typ;
            #[inline]
            fn $fun(self, other: $typ) -> $typ {$typ($base_fun(self.0, other.0))}
        }
        impl $op<&$typ> for $typ {
            type Output = $typ;
            #[inline]
            fn $fun(self, other: &$typ) -> $typ {$typ($base_fun(self.0, other.0))}
        }
        impl $op<$typ> for &$typ {
            type Output = $typ;
            #[inline]
            fn $fun(self, other: $typ) -> $typ {$typ($base_fun(self.0, other.0))}
        }
        impl<'a, 'b> $op<&'b $typ> for &'a $typ {
            type Output = $typ;
            #[inline]
            fn $fun(self, other: &'b $typ) -> $typ {$typ($base_fun(self.0, other.0))}
        }
    }
}

macro_rules! assign_op {
    ($op: ident, $fun: ident, $base_fun: ident, $typ: ident) => {
        impl $op<$typ> for $typ {
            #[inline]
            fn $fun(&mut self, other: $typ) {self.0 = $base_fun(self.0, other.0)}
        }
        impl $op<&$typ> for $typ {
            #[inline]
            fn $fun(&mut self, other: &$typ) {self.0 = $base_fun(self.0, other.0)}
        }
    }
}

macro_rules! fold_op {
    ($op: ident, $fun: ident, $base_fun: path, $id: expr, $typ: ident) => {
        impl $op<$typ> for $typ {
            fn $fun<I: Iterator<Item = $typ>>(iter: I) -> $typ {
                iter.fold($id, $base_fun)
            }
        }
        impl<'a> $op<&'a $typ> for $typ {
            fn $fun<I: Iterator<Item = &'a $typ>>(iter: I) -> $typ {
                iter.fold($id, $base_fun)
            }
        }
    }
}

macro_rules! field_ops {
    ($typ: ident) => {
        use std::ops::{Add, Sub, Mul, Div, Neg};
        use std::ops::{AddAssign, SubAssign, MulAssign, DivAssign};
        use std::iter::{Sum, Product};

        binary_op!{Add, add, add_monty, $typ}
        assign_op!{AddAssign, add_assign, add_monty, $typ}
        fold_op!{Sum, sum, Add::add, $typ(ZERO_MONTY), $typ}

        binary_op!{Sub, sub, sub_monty, $typ}
        assign_op!{SubAssign, sub_assign, sub_monty, $typ}

        binary_op!{Mul, mul, mul_monty, $typ}
        assign_op!{MulAssign, mul_assign, mul_monty, $typ}
        fold_op!{Product, product, Mul::mul, $typ(ONE_MONTY), $typ}

        binary_op!{Div, div, div_monty, $typ}
        assign_op!{DivAssign, div_assign, div_monty, $typ}

        impl Neg for $typ {
            type Output = $typ;
            #[inline]
            fn neg(self) -> $typ {$typ(neg_monty(self.0))}
        }
        impl Neg for &$typ {
            type Output = $typ;
            #[inline]
            fn neg(self) -> $typ {$typ(neg_monty(self.0))}
        }
    }
}

field_ops!{F}

impl std::ops::Rem for F { // doesn't make sense, but needed for Num
    type Output = Self;
    fn rem(self, _: Self) -> Self { Self::ZERO }
}

impl std::cmp::PartialEq for F {
    #[inline]
    fn eq(&self, other: &Self) -> bool { eq_monty(self.0, other.0) }
}

impl std::cmp::Eq for F {}

impl num_traits::identities::One for F {
    #[inline]
    fn one() -> Self { Self::ONE }
}

impl num_traits::identities::Zero for F {
    #[inline]
    fn zero() -> Self { Self::ZERO }
    #[inline]
    fn is_zero(&self) -> bool { *self == Self::ZERO }
}

impl num_traits::Num for F {
    type FromStrRadixErr = core::num::ParseIntError;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        <i128 as num_traits::Num>::from_str_radix(s, r).map(From::from)
    }
}

impl ndarray::ScalarOperand for F { }

impl std::fmt::Debug for F {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[F({}) = {}]", self.0, from_monty(self.0)))
    }
}

impl std::fmt::Display for F {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", from_monty(self.0)))
    }
}

impl Distribution<F> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> F {
        F(rng.gen_range(0, F::MODULUS) as u64)
    }
}

#[cfg(test)]
impl Arbitrary for F {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (0..M as u128).prop_map(|n| Self(to_monty(n))).boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_eq(f in any::<F>()) {
        prop_assert_eq!(f, f);
    }

    #[test]
    fn test_conv_i128(n in any::<i128>()) {
        let n_mod = n % M as i128;
        let n_pos = if n_mod >= 0 { n_mod } else { M as i128 + n_mod };
        prop_assert_eq!(n_pos, i128::from(F::from(n)))
    }

    #[test]
    fn test_conv_u128(n in 0..M as u128) {
        prop_assert_eq!(n % M as u128, u128::from(F::from(n)))
    }

    #[test]
    fn test_conv_u64(n in 0..M) {
        prop_assert_eq!(n % M, u64::from(F::from(n)))
    }

    #[test]
    fn test_conv_bytes(f in any::<F>()) {
        prop_assert_eq!(F::from_bytes(&f.to_bytes()).unwrap(), f)
    }

    #[test]
    fn test_add_neg(f in any::<F>()) {
        prop_assert_eq!(f + f.neg(), F::ZERO);
    }

    #[test]
    fn test_mul_recip(f in any::<F>()) {
        prop_assert_eq!(f * f.inverse(), F::ONE);
    }

    #[test]
    fn test_add(f in any::<F>(), g in any::<F>()) {
        prop_assert_eq!(f + g, F::from(i128::from(f) + i128::from(g)));
    }

    #[test]
    fn test_add_assign(f in any::<F>(), g in any::<F>()) {
        let mut f_ = f;
        f_ += g;
        prop_assert_eq!(f_, F::from(i128::from(f) + i128::from(g)));
    }

    #[test]
    fn test_add_zero(f in any::<F>()) {
        prop_assert_eq!(f + F::ZERO, f);
    }

    #[test]
    fn test_sub(f in any::<F>(), g in any::<F>()) {
        prop_assert_eq!(f - g, F::from(i128::from(f) - i128::from(g)));
    }

    #[test]
    fn test_sum(f0 in any::<F>(), f1 in any::<F>(), f2 in any::<F>()) {
        let fs = vec![f0, f1, f2];
        prop_assert_eq!(fs.iter().sum::<F>(), f0 + f1 + f2);
    }

    #[test]
    fn test_mul(f in any::<F>(), g in any::<F>()) {
        prop_assert_eq!(f * g, F::from(i128::from(f) * i128::from(g)));
    }

    #[test]
    fn test_mul_assign(f in any::<F>(), g in any::<F>()) {
        let mut f_ = f;
        f_ *= g;
        prop_assert_eq!(f_, F::from(i128::from(f) * i128::from(g)));
    }

    #[test]
    fn test_mul_zero(f in any::<F>()) {
        prop_assert_eq!(f * F::ZERO, F::ZERO);
    }

    #[test]
    fn test_mul_one(f in any::<F>()) {
        prop_assert_eq!(f * F::ONE, f);
    }

    #[test]
    fn test_div(q in any::<F>(), g_ in 1..F::MODULUS) {
        let g = F::from(g_);
        let f = q * g;
        prop_assert_eq!(f / g, q);
    }

    #[test]
    fn test_product(f0 in any::<F>(), f1 in any::<F>(), f2 in any::<F>()) {
        let fs = vec![f0, f1, f2];
        prop_assert_eq!(fs.iter().product::<F>(), f0 * f1 * f2);
    }

    #[test]
    fn test_pow(b in any::<F>(), e in 0u128..10_000) {
        let mut naive_pow = F::ONE;
        for _i in 0..e {
            naive_pow *= b;
        }
        prop_assert_eq!(b.pow(e), naive_pow);
    }
}

/* Montgomery field operations for a fixed 64-bit field based on
 * https://en.wikipedia.org/wiki/Montgomery_modular_multiplication and
 * https://github.com/snipsco/rust-threshold-secret-sharing
 */

/* Constants for Montgomery conversion/reduction.
 *
 * Need:
 *      R*R_INV - M*M_TICK = 1
 * Given:
 *      R = 2^64
 *      M is field modulus
 */
const R: u128 = 1<<64;
const R_INV: u64 = 839_386_676_306_787_573;         // R^-1 mod M
const R_CUBE: u64 = 1_323_917_639_155_065_737;      // R^3 mod M
const M: u64 = 1_332_669_751_402_954_753;           // 2^19 * 3^26 + 1
const M_TICK: u64 = 11_618_745_889_904_394_239;     // R - (M^-1} mod R)

const_assert_eq!(montgomery_constants;
    (R*(R_INV as u128) - (M as u128)*(M_TICK as u128)), 1);

/* Operations
 */

#[inline]
fn to_monty(a: u128) -> u64 { ((a << 64) % M as u128) as u64 }

#[inline]
fn redc(a: u128) -> u128 {
    let m = (a as u64).wrapping_mul(M_TICK) as u128;
    let t = ((a + m*(M as u128)) >> 64) as u64;

    (if t >= M as u64 { t - M } else { t }) as u128
}

const ZERO_MONTY: u64 = 0;
const ONE_MONTY: u64 = (R % M as u128) as u64;

#[inline]
fn add_monty(a: u64, b: u64) -> u64 {
    let ab = a + b;

    if ab > M { ab - M } else { ab }
}

#[inline]
fn sub_monty(a: u64, b: u64) -> u64 {
    if a > b { a - b } else { (a as u128 + M as u128 - b as u128) as u64 }
}

#[inline]
fn neg_monty(a: u64) -> u64 { M - a }

#[inline]
fn mul_monty(a: u64, b: u64) -> u64 {
    let ab = (a as u128).wrapping_mul(b as u128);

    redc(ab) as u64
}

#[inline]
fn div_monty(a: u64, b: u64) -> u64 {
    mul_monty(a, inv_monty(b))
}

// Extended GCD based on
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
//
// Given: a, b in Z
// Return: (x, y) s.t.
//      a*x + b*y = g = gcd(a, b)
//      0 <= x < |b/g|
//      -|a/g| < y <= 0
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

#[inline]
fn inv_monty(a: u64) -> u64 {
    if a == 0 { panic!("Division by zero") }
    let a_inv = gcd(a as i128, M as i128).0 as u128;
    redc(a_inv.wrapping_mul(R_CUBE as u128)) as u64
}

#[inline]
fn eq_monty(a: u64, b: u64) -> bool { redc(a as u128) == redc(b as u128) }

#[inline]
fn from_monty(u: u64) -> u128 { (u as u128 * (R_INV as u128)) % M as u128 }

#[cfg(test)]
proptest!{
    #[test]
    fn test_monty_conv(a in 0..M as u128) {
        prop_assert_eq!(a,
            from_monty(
                to_monty(a)))
    }

    #[test]
    fn test_monty_add(a in 0..M as u128, b in 0..M as u128) {
        prop_assert_eq!((a + b) % M as u128,
            from_monty(
                add_monty(
                    to_monty(a),
                    to_monty(b))))
    }

    #[test]
    fn test_monty_add_zero(a in 0..M as u128) {
        prop_assert_eq!(a,
            from_monty(
                add_monty(
                    to_monty(a),
                    ZERO_MONTY)))
    }

    #[test]
    fn test_monty_sub(a in 0..M as u128, b in 0..M as u128) {
        prop_assert_eq!((a + M as u128 - b) % M as u128,
            from_monty(
                sub_monty(
                    to_monty(a),
                    to_monty(b))))
    }

    #[test]
    fn test_monty_neg(a in 0..M as u128) {
        prop_assert_eq!(0u128,
            from_monty(
                add_monty(
                    to_monty(a),
                    neg_monty(
                        to_monty(a)))))
    }

    #[test]
    fn test_monty_mul(a in 0..M as u128, b in 0..M as u128) {
        prop_assert_eq!((a * b) % M as u128,
            from_monty(
                mul_monty(
                    to_monty(a),
                    to_monty(b))))
    }

    #[test]
    fn test_monty_mul_one(a in 0..M as u128) {
        prop_assert_eq!(a,
            from_monty(
                mul_monty(
                    to_monty(a),
                    ONE_MONTY)))
    }

    #[test]
    fn test_monty_mul_zero(a in 0..M as u128) {
        prop_assert_eq!(0,
            from_monty(
                mul_monty(
                    to_monty(a),
                    ZERO_MONTY)))
    }

    #[test]
    fn test_monty_div(b in 1..M as u128, q in 0..M as u128) {
        let a = (b * q) % M as u128;
        prop_assert_eq!(q,
            from_monty(
                div_monty(
                    to_monty(a),
                    to_monty(b))))
    }

    #[test]
    fn test_monty_inv(a in 0..M as u128) {
        prop_assert_eq!(1u128,
            from_monty(
                mul_monty(
                    to_monty(a),
                    inv_monty(
                        to_monty(a)))))
    }

    #[test]
    fn test_monty_eq(a in 0..M as u128, b in 0..M as u128) {
        prop_assert_eq!(a == b,
            eq_monty(
                to_monty(a),
                to_monty(b)));
        prop_assert!(
            eq_monty(
                to_monty(a),
                to_monty(a)));
    }
}
