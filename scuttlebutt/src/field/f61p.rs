use crate::field::{polynomial::Polynomial, BiggerThanModulus, FiniteField, PrimeFiniteField};
use generic_array::GenericArray;
use rand_core::RngCore;
use std::ops::{AddAssign, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(test)]
use proptest::prelude::*;

/// A finite field over the Mersenne Prime 2^61 - 1
#[derive(Clone, Copy, Eq, Debug, Hash)]
pub struct F61p(u64);

const MODULUS: u64 = (1 << 61) - 1;

impl ConstantTimeEq for F61p {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for F61p {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F61p(u64::conditional_select(&a.0, &b.0, choice))
    }
}
impl FiniteField for F61p {
    type Serializer = crate::field::serialization::ByteFiniteFieldSerializer<Self>;
    type Deserializer = crate::field::serialization::ByteFiniteFieldDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U8;
    type FromBytesError = BiggerThanModulus;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        let buf = <[u8; 8]>::from(*bytes);
        let raw = u64::from_le_bytes(buf);
        if raw < MODULUS {
            Ok(F61p(raw))
        } else {
            Err(BiggerThanModulus)
        }
    }

    #[inline]
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }

    type PrimeField = Self;
    type PolynomialFormNumCoefficients = generic_array::typenum::U1;

    #[inline]
    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        coeff[0]
    }

    #[inline]
    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        [*self].into()
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    #[inline]
    fn multiply_by_prime_subfield(&self, pf: Self::PrimeField) -> Self {
        self * pf
    }

    /// This has a 2^-61 probability of being a biased draw.
    #[inline]
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        F61p(reduce(
            u64::from_le_bytes(<[u8; 8]>::try_from(&x[0..8]).unwrap()) as u128,
        ))
    }

    /// This has a 2^-61 probability of being a biased draw.
    #[inline]
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        F61p(reduce(rng.next_u64() as u128))
    }

    // TODO: this generator might be wrong.
    const GENERATOR: Self = F61p(5);
    const ZERO: Self = F61p(0);
    const ONE: Self = F61p(1);

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U61;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        super::standard_bit_decomposition(u128::from(self.0))
    }
    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time(u128::from(MODULUS) - 2)
    }
}

#[inline]
fn reduce(k: u128) -> u64 {
    // Based on https://ariya.io/2007/02/modulus-with-mersenne-prime
    let i = (k & u128::from(MODULUS)) + (k >> 61);
    // Equivalent to:
    /*u64::conditional_select(
        &(i as u64),
        &((i.wrapping_sub(F61p::MODULUS)) as u64),
        Choice::from((i >= F61p::MODULUS) as u8),
    )*/
    let flag = (i < u128::from(MODULUS)) as u128;
    let operand = flag.wrapping_sub(1) & u128::from(MODULUS);
    (i - operand) as u64
}

impl AddAssign<&F61p> for F61p {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let a = self.0 as u128;
        let b = rhs.0 as u128;
        self.0 = reduce(a + b);
    }
}

impl SubAssign<&F61p> for F61p {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        // We add modulus so it can't overflow.
        let a = u128::from(self.0) + u128::from(MODULUS);
        let b = u128::from(rhs.0);
        self.0 = reduce(a - b);
    }
}

impl MulAssign<&F61p> for F61p {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = reduce(u128::from(self.0) * u128::from(rhs.0));
    }
}

impl std::iter::Sum for F61p {
    #[inline]
    // // Naive Implementations
    // fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
    //     //iter.fold(F61p::ZERO, std::ops::Add::add)
    //     let mut a : F61p = F61p::ZERO;
    //     for e in iter {
    //         a += e;
    //     }
    //     return a;
    // }

    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut out: u128 = 0;
        // Invariant: this code is correct if the length of the
        // iterator is less than 2^(128 - 61).
        for e in iter {
            out += u128::from(e.0);
        }
        return F61p(reduce(out));
    }
}

impl TryFrom<u128> for F61p {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < MODULUS.into() {
            // This unwrap should never fail since we check that the value fits
            // in the modulus.
            Ok(F61p(value.try_into().unwrap()))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

impl PrimeFiniteField for F61p {}

field_ops!(F61p, SUM_ALREADY_DEFINED);

#[cfg(test)]
test_field!(test_f61p, F61p);

#[cfg(test)]
proptest! {
    #[test]
    fn test_reduce(x in 0u128..((1 << (2 * 61))-1)) {
        assert_eq!(u128::from(reduce(x)), x % u128::from(MODULUS));
    }
}

#[test]
fn test_generator() {
    assert_eq!(F61p::GENERATOR.pow(u128::from(MODULUS) - 1), F61p::ONE);
}

#[test]
fn test_sum_overflow() {
    let neg1 = F61p::ZERO - F61p::ONE;
    let x = [neg1; 2];
    assert_eq!(x.iter().map(|x| *x).sum::<F61p>(), neg1 + neg1);
}
