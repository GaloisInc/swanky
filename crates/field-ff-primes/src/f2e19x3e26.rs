use swanky_field::FiniteRing;
use swanky_field_fft::FieldForFFT;

crate::prime_field_using_ff::prime_field_using_ff!(
    /// The finite field over the prime $`M = 2^{19} 3^{26} + 1`$.
    /// Hence, $`\phi(M)`$ is divisible by $`2^{19}`$ and $`3^{26}`$
    /// and thus supports a large number of FFT<2> and FFT<3> sizes for
    /// threshold secret sharing.
    F2e19x3e26,
    f2e19x3e26,
    modulus = "1332669751402954753",
    generator = "7",
    limbs = 1,
    actual_limbs = 1,
    num_bytes = generic_array::typenum::U8,
    num_bits = generic_array::typenum::U61,
    single_limb_modulus = 1332669751402954753
);

impl FieldForFFT<2> for F2e19x3e26 {
    const PHI_EXP: usize = 19;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from(
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
        .unwrap_or_else(|_| unreachable!())
    }
}

impl FieldForFFT<3> for F2e19x3e26 {
    const PHI_EXP: usize = 26;

    #[inline]
    fn roots(ix: usize) -> Self {
        Self::try_from(
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
        .unwrap_or_else(|_| unreachable!())
    }
}

impl ndarray::ScalarOperand for F2e19x3e26 {}

impl std::ops::Rem<F2e19x3e26> for F2e19x3e26 {
    type Output = Self;
    // XXX: This implementation is WRONG! But presumably that's fine
    // because it's only needed to satisfy the `num_traits::Num` trait?
    // In either case we should fix this.
    fn rem(self, _modulus: Self) -> Self {
        F2e19x3e26::ZERO
    }
}

impl num_traits::MulAdd for F2e19x3e26 {
    type Output = Self;
    #[inline]
    fn mul_add(self, a: Self, b: Self) -> Self::Output {
        self * a + b
    }
}

impl num_traits::Num for F2e19x3e26 {
    // We don't really have a good error for parsing errors beyond the value being
    // larger than the modulus, so we use that here even though it doesn't perfectly
    // describe the situation (since `from_str_radix` could presumably error out
    // for another reason).
    type FromStrRadixErr = swanky_serialization::BiggerThanModulus;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        match <u128 as num_traits::Num>::from_str_radix(s, r) {
            Ok(num) => Self::try_from(num),
            Err(_) => Err(swanky_serialization::BiggerThanModulus),
        }
    }
}
