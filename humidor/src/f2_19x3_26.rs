#[cfg(test)]
use proptest::{*, prelude::*};

#[derive(Debug, Clone, Copy, Default)]
pub struct F(pub i128);

impl F {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const MOD: i128 = 1332669751402954753; // 2**19 * 3**26 + 1
    pub const PHI: i128 = Self::MOD - 1;
    pub const GEN: Self = Self(7);
    pub const PHI_2_EXP: i128 = 19;
    pub const PHI_3_EXP: i128 = 26;
    pub const BITS: usize = 61; // floor(log2(MOD))

    // [ GEN**(PHI / (2**p)) % MOD | p <- [0 .. PHI_2_EXP] ]
    pub const ROOTS_BASE_2 : [i128; Self::PHI_2_EXP as usize + 1] =
        [ 1,                   1332669751402954752, 973258067192839568
        , 1042021548001376395, 402574676512991381,  278717750013534980
        , 74087475420063438,   566374465489511427,  1266925147139716861
        , 855420670760076263,  644012728790649397,  1024672769443274150
        , 969915203910377054,  938399742097549903,  677395270312196759
        , 638309941020567122,  941411658640200634,  214614403681673597
        , 1142590720645869203, 1081812970925941425];
    // [ GEN**(PHI / (3**p)) % MOD | p <- [0 .. PHI_3_EXP] ]
    pub const ROOTS_BASE_3 : [i128; Self::PHI_3_EXP as usize + 1] =
        [ 1,                   460004726804964255, 669043805643439512
        , 296722197659361911,  374719411438346623, 903621615088971058
        , 528204403879753449,  404018507378766984, 569267202400654075
        , 951499245552476893,  869386426445016020, 231629203731078009
        , 911561347291773360,  985928605492343887, 116593309072767134
        , 200952336485094508,  455485850035128309, 567008847283293789
        , 137993045254182336,  158980184853827215, 1203426293655283518
        , 1214402346646813410, 648772824772841070, 1312084489284135569
        , 59416712983923841,   523602121810241645, 920749240289894275];

    pub fn bytes(self) -> Vec<u8> {
        self.0.to_be_bytes().iter().cloned().collect()
    }

    pub fn positivize(self) -> Self {
        let Self(x) = self;
        (Self::MOD + x).into()
    }

    // XXX: Maybe use montgomery multiplication here? Don't think it's a hot
    // path, though.
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

impl std::iter::Sum for F {
    fn sum<I>(iter: I) -> Self
        where I: Iterator<Item = Self>
    {
        iter.fold(F::ZERO, |acc, f| acc + f)
    }
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

impl std::iter::Product for F {
    fn product<I>(iter: I) -> Self
        where I: Iterator<Item = Self>
    {
        iter.fold(F::ZERO, |acc, f| acc * f)
    }
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

impl ndarray::ScalarOperand for F { }

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
