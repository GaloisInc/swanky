use generic_array::{typenum::U128, GenericArray};

use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{polynomial::Polynomial, FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{BytesDeserializationCannotFail, CanonicalSerialize};
use vectoreyes::{SimdBase, U64x2};

use crate::{F128b, F2};

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

        // Reduce! This reduction code was generated using SageMath as a function of the
        // polynomial modulus selected for the field.
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

// F128b superfield
impl From<F8b> for F128b {
    fn from(value: F8b) -> Self {
        // TODO: performance optimize this
        let mut arr: GenericArray<F8b, generic_array::typenum::U16> = Default::default();
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
    type DegreeModulo = generic_array::typenum::U16;

    fn decompose_superfield(fe: &F128b) -> generic_array::GenericArray<Self, Self::DegreeModulo> {
        // Bitwise multiply the conversion matrix with the input to ensure multiplication is
        // homomorphic between the types
        let converted_input = F128_TO_F8_16
            .into_iter()
            // This is a dot product!
            .map(|row| (row & fe.0).count_ones() % 2 == 1)
            .map(|bit| F2::from(bit))
            .collect::<GenericArray<_, U128>>();

        // Un-flatten the result
        // This unwrap is safe because the chunk size is hardcoded to 8 and the original array
        // length is divisible by 8.
        converted_input
            .chunks(8)
            .map(|chunk| F2::form_superfield(chunk.try_into().unwrap()))
            .collect()
    }

    fn form_superfield(
        components: &generic_array::GenericArray<Self, Self::DegreeModulo>,
    ) -> F128b {
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
            .map(|bit| F2::from(bit))
            .collect();

        F2::form_superfield(&converted_input)
    }
}

impl F8b {
    pub fn get_bit(&self, i: u8) -> u8 {
        self.0 >> i & 1
    }
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use super::*;
    use generic_array::{typenum::U16, GenericArray};
    use proptest::{array::uniform16, prelude::*};
    use swanky_field::{polynomial::Polynomial, IsSubFieldOf};
    use swanky_field_test::arbitrary_ring;
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

        let components = a
            .into_iter()
            .map(|ai| u8_to_f8b(ai))
            .collect::<GenericArray<F8b, U16>>();
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

    fn multiply_f8b_16_elements(
        a: GenericArray<F8b, U16>,
        b: GenericArray<F8b, U16>,
    ) -> GenericArray<F8b, U16> {
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
        let mut out: GenericArray<F8b, U16> = Default::default();
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
            .map(|n| u8_to_f8b(n))
            .collect::<GenericArray<F8b, U16>>();

        let a_squared = multiply_f8b_16_elements(a, a);
        for (e, a) in zip(expected_product, a_squared) {
            assert_eq!(e, a.0)
        }
    }

    swanky_field_test::test_field!(test_field, F8b);

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
            let a: GenericArray<F8b, U16> = a.into();
            let b: GenericArray<F8b, U16> = b.into();

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

/// Conversion matrix used to transform elements in $`\textsf{GF}(2^8)^{16}`$ to
/// $`\textsf{GF}(2^{128})`$.
///
/// This is tailored to produce a sensible isomorphism with our chosen polynomials so that
/// multiplication is homomorphic across the two fields. It was computed using SageMath as a
/// function of the polynomials for `F8b` and `F128b`.
const F8_16_TO_F128: [u128; 128] = [
    0x827ccc967c10d06c2ade106a4a182a1d,
    0xfeb05aea6cc0bc46f4ce7a205232372a,
    0x322626fabcac9698e4a43038782f00ae,
    0x2626fabcac9698e4a43038782f00ae6c,
    0x26fabcac9698e4a43038782f00ae6ca0,
    0xfabcac9698e4a43038782f00ae6ca0f8,
    0xbcac9698e4a43038782f00ae6ca0f8ba,
    0x2eea5472d820e81405debe06eae090d2,
    0xea5472d820e81405debe06eae090d280,
    0x5472d820e81405debe06eae090d2805c,
    0x72d820e81405debe06eae090d2805c56,
    0xd820e81405debe06eae090d2805c5634,
    0x20e81405debe06eae090d2805c563402,
    0xe81405debe06eae090d2805c563402b8,
    0x1405debe06eae090d2805c563402b8c4,
    0x5debe06eae090d2805c563402b8c43e,
    0xdebe06eae090d2805c563402b8c43e6a,
    0xbe06eae090d2805c563402b8c43e6a22,
    0x6eae090d2805c563402b8c43e6a2228,
    0xeae090d2805c563402b8c43e6a2228fa,
    0xe090d2805c563402b8c43e6a2228faea,
    0x90d2805c563402b8c43e6a2228faea46,
    0xd2805c563402b8c43e6a2228faea460e,
    0x805c563402b8c43e6a2228faea460e38,
    0x5c563402b8c43e6a2228faea460e3884,
    0x563402b8c43e6a2228faea460e388440,
    0x3402b8c43e6a2228faea460e388440d4,
    0x2b8c43e6a2228faea460e388440d488,
    0xb8c43e6a2228faea460e388440d488f4,
    0xc43e6a2228faea460e388440d488f47a,
    0x3e6a2228faea460e388440d488f47aae,
    0x6a2228faea460e388440d488f47aaeaa,
    0x2228faea460e388440d488f47aaeaa20,
    0x28faea460e388440d488f47aaeaa2052,
    0xfaea460e388440d488f47aaeaa2052ce,
    0xea460e388440d488f47aaeaa2052ced4,
    0x460e388440d488f47aaeaa2052ced4aa,
    0xe388440d488f47aaeaa2052ced4aa64,
    0x388440d488f47aaeaa2052ced4aa6490,
    0x8440d488f47aaeaa2052ced4aa6490fc,
    0x40d488f47aaeaa2052ced4aa6490fc32,
    0xd488f47aaeaa2052ced4aa6490fc32ca,
    0x88f47aaeaa2052ced4aa6490fc32caaa,
    0xf47aaeaa2052ced4aa6490fc32caaa96,
    0x7aaeaa2052ced4aa6490fc32caaa9690,
    0xaeaa2052ced4aa6490fc32caaa9690a6,
    0xaa2052ced4aa6490fc32caaa9690a616,
    0x2052ced4aa6490fc32caaa9690a6168e,
    0x52ced4aa6490fc32caaa9690a6168ede,
    0xced4aa6490fc32caaa9690a6168ede74,
    0xd4aa6490fc32caaa9690a6168ede747c,
    0xaa6490fc32caaa9690a6168ede747cce,
    0x6490fc32caaa9690a6168ede747cce9c,
    0x90fc32caaa9690a6168ede747cce9cbc,
    0xfc32caaa9690a6168ede747cce9cbcd8,
    0x32caaa9690a6168ede747cce9cbcd8c8,
    0xcaaa9690a6168ede747cce9cbcd8c8e6,
    0xaa9690a6168ede747cce9cbcd8c8e648,
    0x9690a6168ede747cce9cbcd8c8e64852,
    0x90a6168ede747cce9cbcd8c8e648525a,
    0xa6168ede747cce9cbcd8c8e648525ae0,
    0x168ede747cce9cbcd8c8e648525ae05e,
    0x8ede747cce9cbcd8c8e648525ae05e3a,
    0xde747cce9cbcd8c8e648525ae05e3a56,
    0x747cce9cbcd8c8e648525ae05e3a5620,
    0x7cce9cbcd8c8e648525ae05e3a5620c8,
    0xce9cbcd8c8e648525ae05e3a5620c8de,
    0x9cbcd8c8e648525ae05e3a5620c8de8c,
    0xbcd8c8e648525ae05e3a5620c8de8ca6,
    0xd8c8e648525ae05e3a5620c8de8ca608,
    0xc8e648525ae05e3a5620c8de8ca60848,
    0xe648525ae05e3a5620c8de8ca6084850,
    0x48525ae05e3a5620c8de8ca6084850b8,
    0x525ae05e3a5620c8de8ca6084850b874,
    0x5ae05e3a5620c8de8ca6084850b8748a,
    0xe05e3a5620c8de8ca6084850b8748abc,
    0x5e3a5620c8de8ca6084850b8748abc5c,
    0x3a5620c8de8ca6084850b8748abc5cba,
    0x5620c8de8ca6084850b8748abc5cba40,
    0x20c8de8ca6084850b8748abc5cba40dc,
    0xc8de8ca6084850b8748abc5cba40dcd6,
    0xde8ca6084850b8748abc5cba40dcd61e,
    0x8ca6084850b8748abc5cba40dcd61eb6,
    0xa6084850b8748abc5cba40dcd61eb618,
    0x84850b8748abc5cba40dcd61eb618d6,
    0x4850b8748abc5cba40dcd61eb618d610,
    0x50b8748abc5cba40dcd61eb618d6104a,
    0xb8748abc5cba40dcd61eb618d6104a14,
    0x748abc5cba40dcd61eb618d6104a14ee,
    0x8abc5cba40dcd61eb618d6104a14eea0,
    0xbc5cba40dcd61eb618d6104a14eea0f2,
    0x5cba40dcd61eb618d6104a14eea0f2f6,
    0xba40dcd61eb618d6104a14eea0f2f678,
    0x40dcd61eb618d6104a14eea0f2f6786e,
    0xdcd61eb618d6104a14eea0f2f6786e48,
    0xd61eb618d6104a14eea0f2f6786e4836,
    0x1eb618d6104a14eea0f2f6786e483676,
    0xb618d6104a14eea0f2f6786e4836765a,
    0x18d6104a14eea0f2f6786e4836765ac6,
    0xd6104a14eea0f2f6786e4836765ac6ca,
    0x104a14eea0f2f6786e4836765ac6caa4,
    0x4a14eea0f2f6786e4836765ac6caa420,
    0x14eea0f2f6786e4836765ac6caa420de,
    0xeea0f2f6786e4836765ac6caa420de0a,
    0xa0f2f6786e4836765ac6caa420de0ab6,
    0xf2f6786e4836765ac6caa420de0ab6ba,
    0xf6786e4836765ac6caa420de0ab6ba9e,
    0x786e4836765ac6caa420de0ab6ba9e00,
    0x6e4836765ac6caa420de0ab6ba9e001a,
    0x4836765ac6caa420de0ab6ba9e001a70,
    0x36765ac6caa420de0ab6ba9e001a704a,
    0x765ac6caa420de0ab6ba9e001a704a1c,
    0x5ac6caa420de0ab6ba9e001a704a1cec,
    0xc6caa420de0ab6ba9e001a704a1cec82,
    0xcaa420de0ab6ba9e001a704a1cec827c,
    0xa420de0ab6ba9e001a704a1cec827ccc,
    0x20de0ab6ba9e001a704a1cec827ccc96,
    0xde0ab6ba9e001a704a1cec827ccc967c,
    0xab6ba9e001a704a1cec827ccc967c10,
    0xb6ba9e001a704a1cec827ccc967c10d0,
    0xba9e001a704a1cec827ccc967c10d06c,
    0x9e001a704a1cec827ccc967c10d06c2a,
    0x1a704a1cec827ccc967c10d06c2ade,
    0x1a704a1cec827ccc967c10d06c2ade10,
    0x704a1cec827ccc967c10d06c2ade106a,
    0x4a1cec827ccc967c10d06c2ade106a4a,
    0x1cec827ccc967c10d06c2ade106a4a18,
    0xec827ccc967c10d06c2ade106a4a182a,
];

/// Conversion matrix used to transform elements in $`\textsf{GF}(2^{128})`$ to
/// $`\textsf{GF}(2^8)^{16}`$.
///
/// This is tailored to produce a sensible isomorphism with our chosen polynomials so that
/// multiplication is homomorphic across the two fields. It was computed using SageMath as a
/// function of the polynomials for `F8b` and `F128b`; in fact, it's the inverse of the
/// [`F8_16_to_F128`] matrix.
const F128_TO_F8_16: [u128; 128] = [
    0x7b6cf0a9ddfcc4cf65c76c2f8a2a0001,
    0xf758a5acc4d2d4c92789fe43a82f0000,
    0xff400f1720c6aed203164c3772930000,
    0xaf3a49446891dfb5f1b25f193a530000,
    0x179f073d98d4f1d4aa127c9f1fae0000,
    0x85af42f35ce636a3b7e5883cc6190000,
    0xdf7fd2a9f7a53519ce7f26f9a1970000,
    0x70c7a9045cd8ed564457aca72cdb0000,
    0x28a7bc5e2e6ce7c3af5f83c53c7c0002,
    0xa04d2f28df02087e99945c2154330000,
    0x8d93426e76fd2298b0b1b4ec4b60000,
    0x9f0f50eafb9a5d0372a2fe042e830000,
    0xa823303a6a4fddcc4c607e9d0cb70000,
    0xe82ad46180fa1bd8e75fe05947fe0000,
    0x185efbe1c213932398e708ba9d610000,
    0x21772d2732d4647ac85db15c3d330000,
    0x1729849f2d86138ad73dc01f11360004,
    0xbceb90b9381eea574eab53ce11a70000,
    0x7ef26ccfeec7c2cadccc54d160a50000,
    0xadad595692da21cf2986a08fba110000,
    0xcbed324c55655a4a709c13c924c50000,
    0x268eb02264fabfc6380296d519730000,
    0x48e0c695ff07b6f02a9cdae17bba0000,
    0x75ccb224e9f3a5108c5aa1ae01d30000,
    0xcca4e5f4c3e60d34f7dbd83ad7000008,
    0xba9cad4b9e6839fad8ab3d723b860000,
    0xffd497c419638aa96da3737a83a70000,
    0xe2fe7370b7c136bba2031ffad8600000,
    0x7c34ad4db404bfea36a9b081efe50000,
    0xa7f22635b50b2fb60d3ac7da1d360000,
    0x9b6b5b221d1b1f3dde070829d83a0000,
    0xfc84519d88dfbc0fc93dea84ab170000,
    0xeabfa3127dc8a347d575bb6949890010,
    0xc6b57faa8e5d73f7b0fc4cad431f0000,
    0x86f5917a2bd7dea16aba5002cf890000,
    0x616df60886379b5b9424a0642c620000,
    0x1034605813f72728bfcd84ec05e80000,
    0x7945194c47916e37d7a0e4867f790000,
    0xf7ad7426108fdc132dc85065ea510000,
    0xa06bc077dfcc2827eeee09304ded0000,
    0xfcdb8c6c693afbe19229064ca40a0020,
    0xac54ad4fa9e92760063f8ef7dc850000,
    0x493fa26521f06989f357680f032e0000,
    0x6d6397bca712eef8a261ca96d5880000,
    0x26753553461daa666c9b9ce9a390000,
    0xd480f666c087547d7cd507c3b7e0000,
    0x5c54ff98507ebfde21a043c557ae0000,
    0x5ed390246284873e826574af60680000,
    0xf21c41755351de5a05c2cc11eee50040,
    0xa45aa69e1624b3900a662324b7d40000,
    0x9a67ee71a7f4a908c231626adce00000,
    0xfa7ac02e5aaa41c0f2302aa4cf0b0000,
    0xccac41d7c45e767bd264fcbc3d540000,
    0x88a05b021c222df8b26d545baf4b0000,
    0xe2796f6a0bbe7c063ada294fc8d20000,
    0x121f5be56e74d6328ee263004d9c0000,
    0x56b52873761ee7f2a081d30960660080,
    0x6321c92f7a0ed572f835ec0f1a5d0000,
    0x670669a6628e70f473c9a5078d4d0000,
    0x229377eac4d597c7a42ebca76c820000,
    0x9041a6b00e98cda82af8366f29ab0000,
    0xda1390863205ccbe05b8802d9ce20000,
    0xedd42675463b429836ecf74611a30000,
    0x4bfc81a13f1dcd06ac84710bc5ee0000,
    0x35f0c321cb1b7a4fd7caef5a36350100,
    0x1314a4172340eadbceb0964b0d7c0000,
    0xce8ee1a506f0e6129c099f48ad850000,
    0xbae4d22b6a8186a730d1e03e1c880000,
    0xb17c9734b762902b909c69826a30000,
    0xe7ee9449496cbb99fcda61890d490000,
    0xbf4311c52d4aca3086934c486c7e0000,
    0xb574a24eae5809003bc08746ad2a0000,
    0x13bcb715ed166428b4c715202d120200,
    0x69569112b1fa28e59ad2241420350000,
    0xec59d703f0e57dcdad703a1249710000,
    0xf1e55be8283967530772e064c1a90000,
    0x36104f58418fc9cebf7ae7fe9e420000,
    0x6b4c387b7b6c811f29965c8386300000,
    0xe52d71b2db6f75b3e57a7663e5570000,
    0x9c325c7c39be9a77813c58eaccdb0000,
    0x80d9bf3d95456a05c739126a0dd40400,
    0x55b01c6438126fae2de0cf8b73810000,
    0x3bc7ff80d8fc8d04d2748404592e0000,
    0xe2cb3874324295e2a44bbdaa0aed0000,
    0x2bc5dfde539c132e2643a04c6bea0000,
    0xeb927c7c5a7a1afcbf6912bdef840000,
    0xfc7984ab58b5ddc67cbb52b238a40000,
    0x9e47d4a39dc8ca057dfb21dbf0e60000,
    0xddfd6d2d7bf3b56a3e98a596716d0800,
    0xbcff3ff5e8f02e88f1d3e389f8ac0000,
    0xf220bdf2ed1f2caa130c803474450000,
    0xc6a7b117c2597fbd3602dcefde880000,
    0x30d3118563343adea2c290a0e4a10000,
    0x29e74aa235eec795acf0c168933b0000,
    0xabb88efa5fe09e93754711f1f2da0000,
    0x3f3c5a515ea1c788fef9314b9d810000,
    0xba796717563b366aac05e308dc7a1000,
    0xff60fce72bda3fca2ad7e894fc130000,
    0x80281423b8ee11aeb6c977eb10ad0000,
    0xc919d05731012c4b31bca49296330000,
    0x8161819b9a6e50a0c81ea39d7ec30000,
    0x2921d8a017fd175aed1246da92fc0000,
    0x5c5876b0fd091345b084362cf45a0000,
    0xee78bf37bd9d475a343e4ceca0580000,
    0x9f9e351271546051f4008445a9842000,
    0x981aeaba32643fa86adea935f5f30000,
    0x798ea45cab20ef54a7f48c665e820000,
    0xc9608db9689d0792cbd74fc475480000,
    0xc10abde719654befae5a089352510000,
    0x372b51222f1a3d0be05a875554600000,
    0x1d20722c71978be31b848eabfda90000,
    0xa71fbc2f652a4d81762120b17d850000,
    0xb2f43b1c82ff93e8a756c26e3ef4000,
    0xf956bdadaa65e72360e4a0296b7f0000,
    0x81689d0f0d993b39a41fbbf4642d0000,
    0xe1b54160e8d2b1f1d6f641d3ba060000,
    0x1124b1a494c80becebed98e6f4aa0000,
    0xd4c3a2666a9d5b4a4f2ef7f4cfd00000,
    0x884f7c28f07e4b7ae797833af1e10000,
    0xb07ef8ed88a26e9445fa703600260000,
    0x1ec41f31b7a78f9c4befbf7eaa7d8000,
    0xb679fbca22941a8de7ea88584ac20000,
    0x84cd8bfb22e41352fad58d28720e0000,
    0xc8c1db6c50814a7a8c7c432fd2fd0000,
    0xdd8b5eb7cababef1af57a8bd2cd80000,
    0x1a895318a45bb16ce46d0ce71cac0000,
    0xe9ae89a3de04184909660ba18700000,
    0x49593b9383ef6046b33690f237540000,
];
