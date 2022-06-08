// This file is part of `scuttlebutt`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

use crate::field::monty::{monty_from_u128, monty_to_u128, Monty};
use crate::field::{fft::FieldForFFT, PrimeFiniteField};
use crate::{implement_finite_field_for_monty, monty_from_lit};
use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Prime field with modulus `M = 2^19*3^26+1`. Hence `phi(M)` is divisible by
/// `2^19` and `3^26` and supports a large number of fft2 and fft3 sizes for
/// threshold secret sharing.
#[derive(Clone, Copy, Default, Hash, Serialize, Deserialize)]
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
    const M: u64 = 1_332_669_751_402_954_753; // 2^19 * 3^26 + 1
    const M_TICK: u64 = 11_618_745_889_904_394_239; // R - (M^-1} mod R)
    const R_INV: u64 = 839_386_676_306_787_573; // R^-1 mod M

    const G: Self = Self(monty_from_lit!(7, Self::M));
    const BITS: usize = 61;

    type Bits = generic_array::typenum::U61;

    #[inline]
    fn to_raw(&self) -> u64 {
        self.0
    }

    #[inline]
    fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

impl std::convert::From<u64> for F2_19x3_26 {
    #[inline]
    fn from(n: u64) -> Self {
        (n as u128).into()
    }
}

impl std::convert::From<F2_19x3_26> for u64 {
    #[inline]
    fn from(f: F2_19x3_26) -> u64 {
        u128::from(f) as u64
    }
}

impl std::convert::From<u128> for F2_19x3_26 {
    #[inline]
    fn from(n: u128) -> Self {
        monty_from_u128(n)
    }
}

impl std::convert::From<F2_19x3_26> for u128 {
    #[inline]
    fn from(f: F2_19x3_26) -> u128 {
        monty_to_u128(f)
    }
}

impl PrimeFiniteField for F2_19x3_26 {}

implement_finite_field_for_monty! {F2_19x3_26}

impl FieldForFFT<2> for F2_19x3_26 {
    const PHI_EXP: usize = 19;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::from(
            [
                1u128,
                1332669751402954752u128,
                973258067192839568u128,
                1042021548001376395u128,
                402574676512991381u128,
                278717750013534980u128,
                74087475420063438u128,
                566374465489511427u128,
                1266925147139716861u128,
                855420670760076263u128,
                644012728790649397u128,
                1024672769443274150u128,
                969915203910377054u128,
                938399742097549903u128,
                677395270312196759u128,
                638309941020567122u128,
                941411658640200634u128,
                214614403681673597u128,
                1142590720645869203u128,
                1081812970925941425u128,
            ][ix],
        )
    }
}

impl FieldForFFT<3> for F2_19x3_26 {
    const PHI_EXP: usize = 26;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::from(
            [
                1u128,
                460004726804964255u128,
                669043805643439512u128,
                296722197659361911u128,
                374719411438346623u128,
                903621615088971058u128,
                528204403879753449u128,
                404018507378766984u128,
                569267202400654075u128,
                951499245552476893u128,
                869386426445016020u128,
                231629203731078009u128,
                911561347291773360u128,
                985928605492343887u128,
                116593309072767134u128,
                200952336485094508u128,
                455485850035128309u128,
                567008847283293789u128,
                137993045254182336u128,
                158980184853827215u128,
                1203426293655283518u128,
                1214402346646813410u128,
                648772824772841070u128,
                1312084489284135569u128,
                59416712983923841u128,
                523602121810241645u128,
                920749240289894275u128,
            ][ix],
        )
    }
}

impl ndarray::ScalarOperand for F2_19x3_26 {}

impl num_traits::Zero for F2_19x3_26 {
    #[inline]
    fn zero() -> Self {
        <F2_19x3_26 as crate::field::FiniteField>::ZERO
    }
    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl num_traits::One for F2_19x3_26 {
    #[inline]
    fn one() -> Self {
        <F2_19x3_26 as crate::field::FiniteField>::ONE
    }
    #[inline]
    fn is_one(&self) -> bool {
        *self == Self::one()
    }
}

impl std::ops::Rem<F2_19x3_26> for F2_19x3_26 {
    type Output = Self;
    #[inline]
    fn rem(self, _other: Self) -> Self {
        <F2_19x3_26 as crate::field::FiniteField>::ZERO
    }
}

impl num_traits::Num for F2_19x3_26 {
    type FromStrRadixErr = core::num::ParseIntError;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        <u128 as num_traits::Num>::from_str_radix(s, r).map(From::from)
    }
}

#[cfg(test)]
test_field!(test_f2_19x3_26, F2_19x3_26);
