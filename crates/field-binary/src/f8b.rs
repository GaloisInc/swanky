use generic_array::GenericArray;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{polynomial::Polynomial, FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{BytesDeserializationCannotFail, CanonicalSerialize};
use vectoreyes::{SimdBase, U64x2};

use crate::F2;

/// An element of the finite field $`\textsf{GF}({2^{8}})`$ reduced over $`x^8 + x^4 + x^3 + x + 1`$.
#[derive(Debug, Clone, Copy, Hash, Eq)]
pub struct F8b(u8);

impl ConstantTimeEq for F8b {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for F8b {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}
impl<'a> AddAssign<&'a F8b> for F8b {
    fn add_assign(&mut self, rhs: &'a F8b) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F8b> for F8b {
    fn sub_assign(&mut self, rhs: &'a F8b) {
        *self += *rhs;
    }
}

impl<'a> MulAssign<&'a F8b> for F8b {
    fn mul_assign(&mut self, rhs: &'a F8b) {
        // Multiply!
        let a = U64x2::set_lo(self.0 as u64);
        let b = U64x2::set_lo(rhs.0 as u64);
        let wide_product = a.carryless_mul::<false, false>(b);
        let wide_product: u128 = bytemuck::cast(wide_product);

        // Reduce!
        let reduced_product = (wide_product >> 0) & 0b0000000011111111
            ^ (wide_product >> 4) & 0b000011110000
            ^ (wide_product >> 5) & 0b00011111000
            ^ (wide_product >> 7) & 0b011111110
            ^ (wide_product >> 8) & 0b00001111
            ^ (wide_product >> 9) & 0b0001000
            ^ (wide_product >> 10) & 0b111000
            ^ (wide_product >> 11) & 0b01110
            ^ (wide_product >> 12) & 0b1001
            ^ (wide_product >> 13) & 0b111
            ^ (wide_product >> 14) & 0b10
            ^ (wide_product >> 15) & 0b1;

        *self = Self(reduced_product as u8)
    }
}

impl CanonicalSerialize for F8b {
    type ByteReprLen = generic_array::typenum::U1;
    type FromBytesError = BytesDeserializationCannotFail;
    type Serializer = swanky_serialization::ByteElementSerializer<Self>;
    type Deserializer = swanky_serialization::ByteElementDeserializer<Self>;

    fn from_bytes(
        bytes: &generic_array::GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(Self(bytes[0]))
    }

    fn to_bytes(&self) -> generic_array::GenericArray<u8, Self::ByteReprLen> {
        [self.0].into()
    }
}
impl FiniteRing for F8b {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Self(x[0])
    }

    fn random<R: rand::prelude::Rng + ?Sized>(rng: &mut R) -> Self {
        let x: u8 = rng.gen();
        Self(x)
    }
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
}
impl FiniteField for F8b {
    type PrimeField = F2;
    fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
        let mut coefficients = vec![F2::ZERO; 8];
        coefficients[8 - 1] = F2::ONE;
        coefficients[4 - 1] = F2::ONE;
        coefficients[3 - 1] = F2::ONE;
        coefficients[1 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }
    /// The generator is $`g^4 + g + 1`$
    const GENERATOR: Self = Self(0b10011);
    type NumberOfBitsInBitDecomposition = generic_array::typenum::U8;

    fn bit_decomposition(
        &self,
    ) -> generic_array::GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        swanky_field::standard_bit_decomposition(self.0 as u128)
    }

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time((1 << 8) - 2)
    }
}

swanky_field::field_ops!(F8b);

impl From<F2> for F8b {
    fn from(value: F2) -> Self {
        Self(value.0.into())
    }
}
// Prime subfield
impl Mul<F8b> for F2 {
    type Output = F8b;

    fn mul(self, x: F8b) -> Self::Output {
        // Equivalent to:
        // Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
        let new = (!((self.0 as u8).wrapping_sub(1))) & x.0;
        debug_assert!(new == 0 || new == x.0);
        F8b(new)
    }
}
impl IsSubRingOf<F8b> for F2 {}
impl IsSubFieldOf<F8b> for F2 {
    type DegreeModulo = generic_array::typenum::U8;

    fn decompose_superfield(fe: &F8b) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from_iter((0..8).map(|shift| F2::try_from((fe.0 >> shift) & 1).unwrap()))
    }

    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> F8b {
        let mut out = 0;
        for x in components.iter().rev() {
            out <<= 1;
            out |= u8::from(*x);
        }
        F8b(out)
    }
}

#[cfg(test)]
mod tests {
    use super::F8b;
    swanky_field_test::test_field!(test_field, F8b);
}
