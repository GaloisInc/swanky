#[cfg(test)]
use proptest::{*, prelude::*};

#[derive(Clone, Copy, Default)]
pub struct F(u64);

impl F {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(((1u128 << 64) % M as u128) as u64);
    pub const MOD: u64 = M;
    pub const PHI: u64 = Self::MOD - 1;
    pub const GEN: Self = Self(7);
    pub const PHI_2_EXP: u64 = 19;
    pub const PHI_3_EXP: u64 = 26;
    pub const BITS: usize = 61; // floor(log2(MOD))

    // [ GEN**(PHI / (2**p)) % MOD | p <- [0 .. PHI_2_EXP] ]
    pub const ROOTS_BASE_2 : [u64; Self::PHI_2_EXP as usize + 1] =
        [ 1,                   1332669751402954752, 973258067192839568
        , 1042021548001376395, 402574676512991381,  278717750013534980
        , 74087475420063438,   566374465489511427,  1266925147139716861
        , 855420670760076263,  644012728790649397,  1024672769443274150
        , 969915203910377054,  938399742097549903,  677395270312196759
        , 638309941020567122,  941411658640200634,  214614403681673597
        , 1142590720645869203, 1081812970925941425];
    // [ GEN**(PHI / (3**p)) % MOD | p <- [0 .. PHI_3_EXP] ]
    pub const ROOTS_BASE_3 : [u64; Self::PHI_3_EXP as usize + 1] =
        [ 1,                   460004726804964255, 669043805643439512
        , 296722197659361911,  374719411438346623, 903621615088971058
        , 528204403879753449,  404018507378766984, 569267202400654075
        , 951499245552476893,  869386426445016020, 231629203731078009
        , 911561347291773360,  985928605492343887, 116593309072767134
        , 200952336485094508,  455485850035128309, 567008847283293789
        , 137993045254182336,  158980184853827215, 1203426293655283518
        , 1214402346646813410, 648772824772841070, 1312084489284135569
        , 59416712983923841,   523602121810241645, 920749240289894275];

    #[inline]
    pub fn bytes(self) -> Vec<u8> {
        // Assumes field element has undergone modular reduction.
        self.0.to_be_bytes().iter().cloned().collect()
    }

    pub fn pow(self, mut e: u64) -> Self {
        let mut b = self;
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

    // XXX: This is slow. Use GCD. Probably not a hot path, though.
    #[inline]
    pub fn recip(self) -> Self {
        Self(inv_monty(self.0))
    }

    #[inline]
    pub fn neg(self) -> Self {
        let Self(x) = self;
        Self(neg_monty(x))
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

impl std::ops::Add for F {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self { Self(add_monty(self.0, other.0)) }
}

impl std::ops::AddAssign for F {
    #[inline]
    fn add_assign(&mut self, other: Self) { *self = *self + other }
}

impl std::iter::Sum for F {
    fn sum<I>(iter: I) -> Self
        where I: Iterator<Item = Self>
    {
        iter.fold(F::ZERO, std::ops::Add::add)
    }
}

impl std::ops::Sub for F {
    type Output = Self;
    #[inline]
    fn sub(self, other: Self) -> Self { Self(sub_monty(self.0, other.0)) }
}

impl std::ops::SubAssign for F {
    #[inline]
    fn sub_assign(&mut self, other: Self) { *self = *self + other.neg() }
}

impl std::ops::Mul for F {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self { Self(mul_monty(self.0, other.0)) }
}

impl std::ops::MulAssign for F {
    #[inline]
    fn mul_assign(&mut self, other: Self) { *self = *self * other }
}

impl std::iter::Product for F {
    fn product<I>(iter: I) -> Self
        where I: Iterator<Item = Self>
    {
        iter.fold(F::ZERO, std::ops::Mul::mul)
    }
}

impl std::ops::Div for F {
    type Output = Self;
    #[inline]
    fn div(self, other: Self) -> Self { self * other.recip() }
}

impl std::ops::DivAssign for F {
    #[inline]
    fn div_assign(&mut self, other: Self) { *self = *self * other.recip() }
}

impl std::ops::Rem for F { // doesn't make sense, but needed for Num
    type Output = Self;
    fn rem(self, _: Self) -> Self { Self::ZERO }
}

// XXX: Using from_monty is expensive. Is there a better way?
impl std::cmp::PartialEq for F {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        from_monty(self.0) == from_monty(other.0)
    }
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

impl rand::distributions::Distribution<F> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> F {
        F(rng.gen_range(0..F::MOD))
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
    fn test_add_neg(f in any::<F>()) {
        prop_assert_eq!(f + f.neg(), F::ZERO);
    }

    #[test]
    fn test_mul_recip(f in any::<F>()) {
        prop_assert_eq!(f * f.recip(), F::ONE);
    }

    #[test]
    fn test_add(f in any::<F>(), g in any::<F>()) {
        prop_assert_eq!(f + g, F::from(i128::from(f) + i128::from(g)));
    }

    #[test]
    fn test_mul(f in any::<F>(), g in any::<F>()) {
        prop_assert_eq!(f * g, F::from(i128::from(f) * i128::from(g)));
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
const R_INV: u64 = 839_386_676_306_787_573;         // R^-1 mod M
const R_CUBE: u64 = 1_323_917_639_155_065_737;      // R^3 mod M
const M: u64 = 1_332_669_751_402_954_753;           // 2^19 * 3^26 + 1
const M_TICK: u64 = 11_618_745_889_904_394_239;     // 2^64 - (M^-1} mod 2**64)

const_assert_eq!(montgomery_constants;
    ((1u128<<64)*(R_INV as u128) - (M as u128)*(M_TICK as u128)), 1);

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

#[inline]
fn add_monty(a: u64, b: u64) -> u64 {
    let ab = a + b;

    if ab > M { ab - M } else { ab }
}

fn sub_monty(a: u64, b: u64) -> u64 {
    if a > b { a - b } else { (a as u128 + M as u128 - b as u128) as u64 }
}

fn neg_monty(a: u64) -> u64 { M - a }

#[inline]
fn mul_monty(a: u64, b: u64) -> u64 {
    let ab = (a as u128).wrapping_mul(b as u128);

    redc(ab) as u64
}

// XXX: Should change mod_inverse to use u64 instead of i128. Would probably
// speed this up, but by how much?
#[inline]
fn inv_monty(a: u64) -> u64 {
    let ar_inv = crate::numtheory::mod_inverse(a as i128, M as i128);
    let ar_inv_pos = if ar_inv >= 0 { ar_inv } else { M as i128 + ar_inv };
    redc((ar_inv as u128).wrapping_mul(R_CUBE as u128)) as u64
}

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
    fn test_monty_inv(a in 0..M as u128) {
        prop_assert_eq!(1u128,
            from_monty(
                mul_monty(
                    to_monty(a),
                    inv_monty(
                        to_monty(a)))))
    }
}
