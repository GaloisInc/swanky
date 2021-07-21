use std::hash::Hash;

#[cfg(test)]
use proptest::{*, prelude::*};

use crate::field::monty::*;
use crate::{monty_from_lit, implement_finite_field_for_monty};

/// Prime field with modulus `M = 2^19*3^26+1`. Hence `phi(M)` is divisible by
/// `2^19` and `3^26` and supports a large number of fft2 and fft3 sizes for
/// threshold secret sharing.
#[derive(Clone, Copy, Default, Hash)]
pub struct F2_19x3_26(u64);

impl std::fmt::Debug for F2_19x3_26 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "[F({}) = {}]",
            self.0,
            (self.0 as u128 * (Self::R_INV as u128)) % Self::M as u128,
        ))
    }
}

impl Monty for F2_19x3_26 {
    const M: u64 = 1_332_669_751_402_954_753;           // 2^19 * 3^26 + 1
    const M_TICK: u64 = 11_618_745_889_904_394_239;     // R - (M^-1} mod R)
    const R_INV: u64 = 839_386_676_306_787_573;         // R^-1 mod M

    const G: Self = Self(monty_from_lit!(7, Self::M));
    const BITS: usize = 61;

    #[inline]
    fn to_raw(&self) -> u64 { self.0 }

    #[inline]
    fn from_raw(raw: u64) -> Self { Self(raw) }
}

impl std::convert::From<u64> for F2_19x3_26 {
    #[inline]
    fn from(n: u64) -> Self { (n as u128).into() }
}

impl std::convert::From<u128> for F2_19x3_26 {
    #[inline]
    fn from(n: u128) -> Self { monty_from_u128(n) }
}

implement_finite_field_for_monty!{F2_19x3_26}

impl crate::numtheory::FieldForFFT2 for F2_19x3_26 {
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

impl crate::numtheory::FieldForFFT3 for F2_19x3_26 {
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

impl ndarray::ScalarOperand for F2_19x3_26 {}

impl num_traits::Zero for F2_19x3_26 {
    #[inline]
    fn zero() -> Self { <F2_19x3_26 as crate::field::FiniteField>::ZERO }
    #[inline]
    fn is_zero(&self) -> bool { *self == Self::zero() }
}

impl num_traits::One for F2_19x3_26 {
    #[inline]
    fn one() -> Self { <F2_19x3_26 as crate::field::FiniteField>::ONE }
    #[inline]
    fn is_one(&self) -> bool { *self == Self::one() }
}

impl std::ops::Rem<F2_19x3_26> for F2_19x3_26 {
    type Output = Self;
    #[inline]
    fn rem(self, _other: Self) -> Self { <F2_19x3_26 as crate::field::FiniteField>::ZERO }
}

impl num_traits::Num for F2_19x3_26 {
    type FromStrRadixErr = core::num::ParseIntError;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        <u128 as num_traits::Num>::from_str_radix(s, r).map(From::from)
    }
}

#[cfg(test)]
test_field!(test_f2_19x3_26, F2_19x3_26);
