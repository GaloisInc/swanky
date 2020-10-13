//! This module has implementations for a specific prime finite field.
//!
//! # Security Warning
//! TODO: this might not be constant-time in all cases.

use crate::{
    field::{polynomial::Polynomial, FiniteField},
    Block,
};
use generic_array::GenericArray;
use primitive_types::{U128, U256};
use rand_core::RngCore;
use std::{
    convert::TryFrom,
    hash::Hash,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the prime-order finite field $\textsf{GF}(2^{128} - 159)$
///
/// This is called `Fp` because it is our "common" prime-order finite field.
#[derive(Debug, Eq, Clone, Copy, Hash)]
pub struct Fp(u128);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl Fp {
    // This function is required by the uint_full_mul_reg macro
    #[inline(always)]
    const fn split_u128(a: u128) -> (u64, u64) {
        ((a >> 64) as u64, a as u64)
    }
}

impl FiniteField for Fp {
    /// There is a slight bias towards the range $[0,158]$.
    /// There is a $\frac{159}{2^128} \approx 4.6 \times 10^{-37}$ chance of seeing this bias.
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes[..]);
        Self::try_from(u128::from_le_bytes(bytes) % Self::MODULUS).unwrap()
    }

    const ZERO: Self = Fp(0);

    const ONE: Self = Fp(1);

    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = BiggerThanModulus;

    /// If the given value is greater than the modulus, then reduce the value by the modulus. Although,
    /// the output of this function is biased in that case, it is less probability that the number greater than the
    /// modulus.
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        let mut value = u128::from_le_bytes(*x);
        if value > Self::MODULUS {
            value %= Self::MODULUS
        }
        Fp(value)
    }
    /// If you put random bytes into here, while it's _technically_ biased, there's only a tiny
    /// chance that you'll get biased output.
    fn from_bytes(buf: &GenericArray<u8, Self::ByteReprLen>) -> Result<Self, BiggerThanModulus> {
        Fp::try_from(u128::from_le_bytes(*buf.as_ref()))
    }

    /// Return the canonical byte representation (byte representation of the reduced field element).
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        u128::from(*self).to_le_bytes().into()
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = Self::MODULUS - 1;

    /// The prime field modulus: $2^{128} - 159$
    const MODULUS: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297;

    const GENERATOR: Self = Fp(5);

    type PrimeField = Self;
    type PolynomialFormNumCoefficients = generic_array::typenum::U1;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        coeff[0]
    }

    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        GenericArray::from([*self])
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        self * pf
    }
}

/// The error which occurs if the inputted `u128` or bit pattern doesn't correspond to a field
/// element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u128> for Fp {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < Self::MODULUS {
            Ok(Fp(value))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

impl TryFrom<Block> for Fp {
    type Error = BiggerThanModulus;

    fn try_from(value: Block) -> Result<Self, Self::Error> {
        let val = u128::from(value);
        Fp::try_from(val)
    }
}

/// This returns a canonical/reduced form of the field element.
impl From<Fp> for u128 {
    #[inline]
    fn from(x: Fp) -> Self {
        x.0
    }
}

impl Default for Fp {
    fn default() -> Self {
        Fp::ZERO
    }
}

// TODO: there's definitely room for optimization. We don't need to use the full mod algorithm here.
impl AddAssign<&Fp> for Fp {
    fn add_assign(&mut self, rhs: &Fp) {
        let mut raw_sum = U256::from(self.0).checked_add(U256::from(rhs.0)).unwrap();
        if raw_sum >= U256::from(Self::MODULUS) {
            raw_sum -= U256::from(Self::MODULUS);
        }
        self.0 = raw_sum.as_u128();
    }
}

impl SubAssign<&Fp> for Fp {
    fn sub_assign(&mut self, rhs: &Fp) {
        let mut raw_diff = (U256::from(self.0) + U256::from(Self::MODULUS))
            .checked_sub(U256::from(rhs.0))
            .unwrap();
        if raw_diff >= U256::from(Self::MODULUS) {
            raw_diff -= U256::from(Self::MODULUS);
        }
        debug_assert!(raw_diff < U256::from(Self::MODULUS));
        self.0 = raw_diff.as_u128();
    }
}

impl MulAssign<&Fp> for Fp {
    fn mul_assign(&mut self, rhs: &Fp) {
        let raw_prod = U256(uint::uint_full_mul_reg!(
            U128,
            2,
            U128::from(self.0),
            U128::from(rhs.0)
        ));
        self.0 = (raw_prod % U256::from(Self::MODULUS)).as_u128();
    }
}

field_ops!(Fp);

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use proptest::prelude::*;

    fn any_f() -> impl Strategy<Value = Fp> {
        any::<u128>().prop_map(|x| Fp(x % Fp::MODULUS))
    }

    macro_rules! test_binop {
        ($name:ident, $op:ident) => {
            proptest! {
                #[test]
                fn $name(mut a in any_f(), b in any_f()) {
                    let mut x = BigUint::from(a.0);
                    let y = BigUint::from(b.0);
                    a.$op(&b);
                    // This is a hack! That's okay, this is a test!
                    if stringify!($op) == "sub_assign" {
                        x += BigUint::from(Fp::MODULUS);
                    }
                    x.$op(&y);
                    x = x % BigUint::from(Fp::MODULUS);
                    assert_eq!(BigUint::from(a.0), x);
                }
            }
        };
    }

    test_binop!(test_add, add_assign);
    test_binop!(test_sub, sub_assign);
    test_binop!(test_mul, mul_assign);

    #[cfg(test)]
    test_field!(test_fp, Fp);

    proptest! {
        #[test]
        fn check_pow(x in any_f(), n in any::<u128>()) {
            let m = BigUint::from(Fp::MODULUS);
            let exp = BigUint::from(n);
            let a = BigUint::from(u128::from(x));
            let left = BigUint::from(u128::from(x.pow(n)));
            assert_eq!(left, a.modpow(&exp, &m));
        }
    }
    #[test]
    fn check_corr() {
        let u: Vec<Fp> = vec![
            Fp(242256444999462856214551029233508406333),
            Fp(131833503718933403974719454723484645942),
            Fp(260136975148194392129736302957675952574),
            Fp(71728935021159247909062611152669882676),
        ];
        let w: Vec<Fp> = vec![
            Fp(279027290371778313484579028735477287641),
            Fp(328844460009071562115264386171123252611),
            Fp(227438299684278229150871680540407386872),
            Fp(182732105224241788881212207952364483696),
        ];
        let v: Vec<Fp> = vec![
            Fp(86079279175282050405483320181225719635),
            Fp(208820581557457178000798197085822441467),
            Fp(227701328647973260363888381983449469696),
            Fp(21453791067848769030224980095060921239),
        ];
        let delta: Fp = Fp(144178984703484722280478643513001652850);

        for i in 0..4 {
            println!("correlation {} is {:?}", i, w[i] == u[i] * delta + v[i]);
            assert_eq!(w[i], u[i] * delta + v[i]);
        }
    }
    #[test]
    fn check_sps_corr() {
        let u = [
            Fp(5),
            Fp(0),
            Fp(0),
            Fp(0),
            Fp(0),
            Fp(0),
            Fp(5),
            Fp(0),
            Fp(5),
            Fp(0),
            Fp(0),
            Fp(0),
        ];
        let w = [
            Fp(334469846995317182142992275384835229544),
            Fp(206268487815441938764904671938420589553),
            Fp(143689624031050923404496915569963889679),
            Fp(267388012659254285385735661767223970981),
            Fp(312923141098377980797233433020512645899),
            Fp(199840102992017703916488816700543560203),
            Fp(162979176940785702539677001712819162780),
            Fp(260175289996584573483463124507090458302),
            Fp(36803805704849454912915572512354397264),
            Fp(203541727889559306246790478776185758338),
            Fp(52873900045395160437089431667609702592),
            Fp(138114232538740076331512587618482614481),
        ];

        let v = [
            Fp(251919918519210849953253344823743947089),
            Fp(206268487815441938764904671938420589553),
            Fp(143689624031050923404496915569963889679),
            Fp(267388012659254285385735661767223970981),
            Fp(312923141098377980797233433020512645899),
            Fp(199840102992017703916488816700543560203),
            Fp(80429248464679370349938071151727880325),
            Fp(260175289996584573483463124507090458302),
            Fp(294536244149681586186551249383031326106),
            Fp(203541727889559306246790478776185758338),
            Fp(52873900045395160437089431667609702592),
            Fp(138114232538740076331512587618482614481),
        ];
        let delta = Fp(16509985695221266437947786112218256491);
        for i in 0..12 {
            assert_eq!(w[i], u[i] * delta + v[i]);
        }
    }
    #[test]
    fn check_zx_corr() {
        let xs = [
            Fp(44530216966177310578974434707826113131),
            Fp(43139089886626563994976322267402273693),
            Fp(14405524150261884711747209257815798445),
            Fp(38207201694756929580983963251229968497),
            Fp(156039715077822553502337612241521761905),
            Fp(310343814034697782801569752673596369257),
            Fp(175075447201634201838963561792772325312),
            Fp(196206219684026688366469145898414405260),
            Fp(156869404707796176898285283704733961526),
            Fp(286960424121547504227532288546512568666),
            Fp(138820882709271621435214018749285316180),
            Fp(3257693159620319243685098416638825652),
        ];
        let zs = [
            Fp(139342347531547200153659849529425487249),
            Fp(6298811602232454453915313362675659649),
            Fp(270537561730555324182934760689743312789),
            Fp(311949232054359545405601242540742084887),
            Fp(176338060492827637155996521868411254023),
            Fp(330461155836719353301487711472215799205),
            Fp(314368603512200159495355076448615605075),
            Fp(111678917366143758016322395978305056840),
            Fp(90487964841566764769166015533610728810),
            Fp(144334735636655374803610230104629180857),
            Fp(71601842306265132248811650017788703371),
            Fp(217331588344689150658086756580085314286),
        ];
        let ys = [
            Fp(56590352206656299338156811780444484685),
            Fp(45784038355854126317813905642254001982),
            Fp(165022231640164839410946156459843841292),
            Fp(149761720411062681293870986053873751440),
            Fp(318434460809591337744739051310017762188),
            Fp(215264394746230847245844150528759259085),
            Fp(5294087282646692185006560830173602952),
            Fp(336991764544565074483579167311981639971),
            Fp(168322953421391318990433340945414446586),
            Fp(330233200702449111304713045038301660782),
            Fp(217260898038304106303776922006084808748),
            Fp(316407408068121781785318802413192316336),
        ];
        let svole_delta = Fp(142208062468075192364984221054444046129);
        let sp_vole_delta = Fp(204751010418423274509128031047234442689);
    }
}
