use hybrid_array::{Array, typenum::U128};
use rand::RngExt;

use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{BytesDeserializationCannotFail, CanonicalSerialize};
use vectoreyes::{SimdBase, U64x2};

use crate::{F2, F128b};

/// An element of the finite field $`\textsf{GF}({2^{8}})`$ reduced over $`x^8 + x^4 + x^3 + x + 1`$.
#[derive(Debug, Clone, Copy, Hash, Eq)]
pub struct F8b(u8);

#[cfg(test)]
use swanky_polynomial::Polynomial;

/// Return the reduction polynomial for the field `F8b`.
#[cfg(test)]
#[allow(clippy::eq_op)]
fn polynomial_modulus_f8b() -> Polynomial<F2> {
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
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &'a F8b) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F8b> for F8b {
    #[allow(clippy::suspicious_op_assign_impl)]
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

        // Reduce! This reduction code was generated using SageMath as a function of the
        // polynomial modulus selected for the field.
        let reduced_product = wide_product & 0b0000000011111111
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
    type ByteReprLen = hybrid_array::typenum::U1;
    type FromBytesError = BytesDeserializationCannotFail;
    type Serializer = swanky_serialization::ByteElementSerializer<Self>;
    type Deserializer = swanky_serialization::ByteElementDeserializer<Self>;

    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        Ok(Self(bytes[0]))
    }

    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        [self.0].into()
    }
}
impl FiniteRing for F8b {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        Self(x[0])
    }

    fn random<R: rand::prelude::Rng + ?Sized>(rng: &mut R) -> Self {
        let x: u8 = rng.random();
        Self(x)
    }
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
}
impl FiniteField for F8b {
    type PrimeField = F2;
    /// The generator is $`g^4 + g + 1`$
    const GENERATOR: Self = Self(0b10011);
    type NumberOfBitsInBitDecomposition = hybrid_array::typenum::U8;

    fn bit_decomposition(&self) -> Array<bool, Self::NumberOfBitsInBitDecomposition> {
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
        Self(value.0)
    }
}

impl From<u8> for F8b {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

// Prime subfield
impl Mul<F8b> for F2 {
    type Output = F8b;

    fn mul(self, x: F8b) -> Self::Output {
        // Equivalent to:
        // Self::conditional_select(&Self::ZERO, &self, pf.ct_eq(&F2::ONE))
        let new = (!(self.0.wrapping_sub(1))) & x.0;
        debug_assert!(new == 0 || new == x.0);
        F8b(new)
    }
}
impl IsSubRingOf<F8b> for F2 {}
impl IsSubFieldOf<F8b> for F2 {
    type DegreeModulo = hybrid_array::typenum::U8;

    fn decompose_superfield(fe: &F8b) -> Array<Self, Self::DegreeModulo> {
        Array::from_iter((0..8).map(|shift| F2::try_from((fe.0 >> shift) & 1).unwrap()))
    }

    fn form_superfield(components: &Array<Self, Self::DegreeModulo>) -> F8b {
        let mut out = 0;
        for x in components.iter().rev() {
            out <<= 1;
            out |= u8::from(*x);
        }
        F8b(out)
    }
}

// F128b superfield
impl From<F8b> for F128b {
    fn from(value: F8b) -> Self {
        // TODO: performance optimize this
        let mut arr: Array<F8b, hybrid_array::typenum::U16> = Default::default();
        arr[0] = value;
        Self::from_subfield(&arr)
    }
}
impl Mul<F128b> for F8b {
    type Output = F128b;

    fn mul(self, x: F128b) -> Self::Output {
        // TODO: performance optimize this
        F128b::from(self) * x
    }
}
impl IsSubRingOf<F128b> for F8b {}
impl IsSubFieldOf<F128b> for F8b {
    type DegreeModulo = hybrid_array::typenum::U16;

    fn decompose_superfield(fe: &F128b) -> Array<Self, Self::DegreeModulo> {
        // Bitwise multiply the conversion matrix with the input to ensure multiplication is
        // homomorphic between the types
        let converted_input = F128_TO_F8_16
            .into_iter()
            // This is a dot product!
            .map(|row| (row & fe.0).count_ones() % 2 == 1)
            .map(F2::from)
            .collect::<Array<_, U128>>();

        // Un-flatten the result
        // This unwrap is safe because the chunk size is hardcoded to 8 and the original array
        // length is divisible by 8.
        converted_input
            .chunks(8)
            .map(|chunk| F2::form_superfield(chunk.try_into().unwrap()))
            .collect()
    }

    fn form_superfield(components: &Array<Self, Self::DegreeModulo>) -> F128b {
        // Flatten the input
        let mut input_bits = 0u128;
        for x in components.iter().rev() {
            input_bits <<= 8;
            input_bits |= u128::from(x.0)
        }

        // Bit-wise multiply the conversion matrix with the input.
        // This is needed to ensure the homomorphic property of multiplication is maintained
        // between the two representations.
        let converted_input = F8_16_TO_F128
            .into_iter()
            // This is a dot product over bits!
            .map(|row| (row & input_bits).count_ones() % 2 == 1)
            .map(F2::from)
            .collect();

        F2::form_superfield(&converted_input)
    }
}

mod conversion_matrices;
use conversion_matrices::*;

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use super::*;
    use hybrid_array::{Array, typenum::U16};
    use proptest::{array::uniform16, prelude::*};
    use swanky_field::IsSubFieldOf;
    use swanky_field_test::arbitrary_ring;
    use swanky_polynomial::Polynomial;
    use vectoreyes::array_utils::ArrayUnrolledExt;

    /// Convenience method to convert from u8s to `F8b`s.
    ///
    /// This matches the behavior of [SageMath's `from_integer`](https://doc.sagemath.org/html/en/reference/finite_rings/sage/rings/finite_rings/finite_field_ntl_gf2e.html#sage.rings.finite_rings.finite_field_ntl_gf2e.FiniteField_ntl_gf2e.from_integer)
    /// method and is therefore convenient for use in the `known_value` tests that follow.
    /// However, this behavior is not necessarily correct for other settings and so this
    /// method should not be used outside of testing.
    fn u8_to_f8b(value: u8) -> F8b {
        F8b(value)
    }

    #[test]
    fn superfield_formation_works_for_known_value() {
        // This uses ground truth values generated by SageMath:
        let a: [u8; 16] = [
            50, 71, 103, 3, 68, 65, 2, 2, 41, 130, 123, 179, 233, 165, 82, 34,
        ];
        let expected: u128 = 219610548346926296185712982125207782468;

        let components = a.into_iter().map(u8_to_f8b).collect::<Array<F8b, U16>>();
        let actual: F128b = F8b::form_superfield(&components);

        assert_eq!(actual.0, expected);
    }

    #[test]
    fn subfield_decomposition_works_for_known_value() {
        // This uses the same ground truth values generated by SageMath:
        let a: u128 = 219610548346926296185712982125207782468;
        let expected: [u8; 16] = [
            50, 71, 103, 3, 68, 65, 2, 2, 41, 130, 123, 179, 233, 165, 82, 34,
        ];

        let actual = F8b::decompose_superfield(&F128b(a));

        for (e, a) in zip(expected, actual) {
            assert_eq!(e, a.0)
        }
    }

    fn multiply_f8b_16_elements(a: Array<F8b, U16>, b: Array<F8b, U16>) -> Array<F8b, U16> {
        // Represent the f8b_16 elements as coefficients for a polynomial
        let [a, b] = [a, b].array_map(|coeffs| Polynomial {
            constant: coeffs[0],
            coefficients: coeffs[1..].to_vec(),
        });

        // Multiply the two polynomials...
        let mut wide_product = a;
        wide_product *= &b;

        // ...then reduce by their modulus. This modulus is a function of the polynomials for the
        // F8b and F128b fields, computed using SageMath.
        // X8^16 + (G8^3 + 1)*X8^15 + (G8^6 + G8^2 + G8 + 1)*X8^14 + (G8^7 + G8^6 + G8^4 + G8)*X8^13 + (G8^4 + G8^3 + G8^2 + G8)*X8^12 + (G8^7 + G8^5 + G8^4 + G8^2 + 1)*X8^11 + (G8^3 + G8)*X8^10 + (G8^7 + G8^6 + G8^3 + G8^2 + G8)*X8^9 + (G8^5 + G8^4 + G8^2 + 1)*X8^8 + (G8^6 + G8^4 + G8^2 + G8)*X8^7 + (G8^5 + G8^3 + 1)*X8^6 + (G8^4 + G8)*X8^5 + (G8^7 + G8^6 + G8^5 + G8^2 + G8 + 1)*X8^4 + (G8^7 + G8^4 + G8^2)*X8^3 + (G8^7 + G8^5 + G8^4 + G8^3 + G8^2 + G8)*X8^2 + (G8^7 + G8^6 + G8^4 + G8^3 + G8)*X8 + G8^7 + G8^6 + G8^5 + G8^3 + G8^2 + G8
        let p16_over_8 = Polynomial {
            constant: F8b(238),
            coefficients: vec![
                F8b(218),
                F8b(190),
                F8b(148),
                F8b(231),
                F8b(18),
                F8b(41),
                F8b(86),
                F8b(53),
                F8b(206),
                F8b(10),
                F8b(181),
                F8b(30),
                F8b(210),
                F8b(71),
                F8b(9),
                F8b(1),
            ],
        };
        let mut reduced_product = wide_product.divmod(&p16_over_8).1;

        // Drop any leading zero coefficients and encode back into an array
        while let Some(x) = reduced_product.coefficients.last() {
            if *x == F8b::ZERO {
                reduced_product.coefficients.pop();
            } else {
                break;
            }
        }
        let mut out: Array<F8b, U16> = Default::default();
        out[0] = reduced_product.constant;
        out[1..1 + reduced_product.coefficients.len()]
            .copy_from_slice(&reduced_product.coefficients);
        out
    }

    #[test]
    fn muliply_f8b_16_elements_works_for_known_value() {
        // Tests multiplication against ground truth from SageMath:
        let expected_product = [
            36, 38, 68, 89, 231, 202, 205, 137, 64, 204, 182, 95, 83, 254, 119, 14,
        ];
        let a = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            .into_iter()
            .map(u8_to_f8b)
            .collect::<Array<F8b, U16>>();

        let a_squared = multiply_f8b_16_elements(a, a);
        for (e, a) in zip(expected_product, a_squared) {
            assert_eq!(e, a.0)
        }
    }

    swanky_field_test::test_field!(test_field, F8b, crate::f8b::polynomial_modulus_f8b);

    fn any_f8b() -> impl Strategy<Value = F8b> {
        arbitrary_ring::<F8b>()
    }
    fn any_f128b() -> impl Strategy<Value = F128b> {
        arbitrary_ring::<F128b>()
    }

    proptest! {
        #[test]
        fn decompose_then_form_works(original in any_f128b()) {
            let composed: F128b = F8b::form_superfield(&F8b::decompose_superfield(&original));
            prop_assert_eq!(original, composed);
        }
    }
    proptest! {
        #[test]
        fn form_then_decompose_works(a in uniform16(any_f8b())) {
            let a_as_ga = a.into();
            let lifted: F128b = F8b::form_superfield(&a_as_ga);
            let composed = F8b::decompose_superfield(&lifted);
            prop_assert_eq!(a_as_ga, composed);
        }
    }
    proptest! {
        #[test]
        fn decompose_homomorphism_works(a in any_f128b(), b in any_f128b()) {
            // decompose(a * b)
            let expected = F8b::decompose_superfield(&(a * b));

            // decompose(a) * decompose(b)
            let a_decomp = F8b::decompose_superfield(&a);
            let b_decomp = F8b::decompose_superfield(&b);
            let actual = multiply_f8b_16_elements(a_decomp, b_decomp);

            prop_assert_eq!(expected, actual);
    }

    }

    proptest! {
        #[test]
        fn superfield_homomorphism_works(a in uniform16(any_f8b()), b in uniform16(any_f8b())) {
            let a: Array<F8b, U16> = a.into();
            let b: Array<F8b, U16> = b.into();

            // superfield(a * b)
            let expected: F128b = F8b::form_superfield(&multiply_f8b_16_elements(a, b));

            // superfield(a) * superfield(b)
            let a_super: F128b = F8b::form_superfield(&a);
            let b_super: F128b = F8b::form_superfield(&b);
            let actual = a_super * b_super;

            prop_assert_eq!(expected, actual);
        }
    }
}
