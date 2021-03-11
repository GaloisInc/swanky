#[cfg(test)]
use proptest::{*, prelude::*};

#[derive(Debug, Clone, Copy, Default)]
pub struct F(pub i128);

impl F {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const MOD: i128 = 5038849; // 2**8 * 3**9 + 1
    pub const PHI: i128 = Self::MOD - 1;
    pub const GEN: Self = Self(29);
    pub const PHI_2_EXP: i128 = 8;
    pub const PHI_3_EXP: i128 = 9;
    pub const BITS: usize = 22; // floor(log2(MOD))

    // [ GEN**(PHI / (2**p)) % MOD | p <- [0 .. PHI_2_EXP] ]
    pub const ROOTS_BASE_2 : [i128; Self::PHI_2_EXP as usize + 1] =
        [1, 5038848, 4695727, 2653925, 4169754, 3835586, 461362, 1759713, 4318906];
    // [ GEN**(PHI / (2**p)) % MOD | p <- [0 .. PHI_3_EXP] ]
    pub const ROOTS_BASE_3 : [i128; Self::PHI_3_EXP as usize + 1] =
        [1, 2517480, 826430, 2522883, 1582093, 2737326, 1556385, 14459, 855021, 1814687];

    pub fn bytes(self) -> Vec<u8> { self.0.to_be_bytes().iter().cloned().collect() }

    pub fn positivize(self) -> Self {
        let Self(x) = self;
        (Self::MOD + x).into()
    }

    pub fn pow(self, mut e: i128) -> Self {
        debug_assert!(e >= 0); // Ensure logical shift
        let Self(mut b) = self;
        let mut acc = 1;

        while e != 0 {
            if e & 0b1 == 0b1 {
                acc = (b * acc) % Self::MOD;
            }
            b = (b * b) % Self::MOD;
            e >>= 1;
        }

        Self(acc)
    }

    pub fn recip(self) -> Self {
        self.pow(Self::PHI - 1)
    }

    pub fn neg(self) -> Self {
        let Self(x) = self;
        (Self::MOD - x).into()
    }
}

impl std::convert::From<i128> for F {
    fn from (n: i128) -> F { F(n % Self::MOD) }
}

impl std::convert::From<F> for i128 {
    fn from (F(n): F) -> i128 { n }
}

impl std::ops::Add for F {
    type Output = Self;
    fn add(self, other: Self) -> Self { (self.0 + other.0).into() }
}

impl std::ops::AddAssign for F {
    fn add_assign(&mut self, other: Self) { *self = *self + other }
}

impl std::ops::Sub for F {
    type Output = Self;
    fn sub(self, other: Self) -> Self { self + other.neg() }
}

impl std::ops::SubAssign for F {
    fn sub_assign(&mut self, other: Self) { *self = *self + other.neg() }
}

impl std::ops::Mul for F {
    type Output = Self;
    fn mul(self, other: Self) -> Self { (self.0 * other.0).into() }
}

impl std::ops::MulAssign for F {
    fn mul_assign(&mut self, other: Self) { *self = *self * other }
}

impl std::ops::Div for F {
    type Output = Self;
    fn div(self, other: Self) -> Self { self * other.recip() }
}

impl std::ops::DivAssign for F {
    fn div_assign(&mut self, other: Self) { *self = *self * other.recip() }
}

impl std::ops::Rem for F { // doesn't make sense, but needed for Num
    type Output = Self;
    fn rem(self, _: Self) -> Self { Self::ZERO }
}

impl std::cmp::PartialEq for F {
    fn eq(&self, other: &Self) -> bool {
        self.positivize().0 == other.positivize().0
    }
}

impl std::cmp::Eq for F {}

impl num_traits::identities::One for F {
    fn one() -> Self { Self::ONE }
}

impl num_traits::identities::Zero for F {
    fn zero() -> Self { Self::ZERO }
    fn is_zero(&self) -> bool { *self == Self::ZERO }
}

impl num_traits::Num for F {
    type FromStrRadixErr = core::num::ParseIntError;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        <i128 as num_traits::Num>::from_str_radix(s, r).map(From::from)
    }
}

impl std::fmt::Display for F {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.positivize().0)
    }
}

#[cfg(test)]
impl Arbitrary for F {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<i128>().prop_map(F::from).boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    #[allow(non_snake_case)]
    fn test_eq(x: i128) {
        let f = F::from(x);
        assert_eq!(f, f.positivize());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_add_neg(x: i128) {
        let f = F::from(x);
        assert_eq!(f + f.neg(), F::ZERO);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_mul_recip(x: i128) {
        let f = F::from(x);
        assert_eq!(f * f.recip(), F::ONE);
    }
}
