use crate::F2;
use generic_array::GenericArray;
use rand::Rng;
use std::iter::FromIterator;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{polynomial::Polynomial, FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use vectoreyes::{U64x2, U8x16};

/// An element of the finite field $\textsf{GF}(2^{128})$ reduced over $x^{128} + x^7 + x^2 + x + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We use a u128 since Rust will pass it in registers, unlike a __m128i
pub struct F128b(pub(crate) u128);

impl ConstantTimeEq for F128b {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for F128b {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F128b(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a F128b> for F128b {
    #[inline]
    fn add_assign(&mut self, rhs: &'a F128b) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F128b> for F128b {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a F128b) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}

mod multiply {
    use vectoreyes::SimdBase8;

    use super::*;

    // TODO: this implements a simple algorithm that works. There are faster algorithms.
    // Maybe we'll implement one, one day...

    // See https://is.gd/tOd246 pages 12-16. Note, their notation [x_1:x_0] means that x_1 is
    // the most-significant half of the resulting number.
    // This function is based on https://git.io/JUUQt
    // The original code is MIT/Apache 2.0 dual-licensed.
    // See: https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
    // See: https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html
    // See: https://tools.ietf.org/html/rfc8452

    #[inline(always)]
    fn upper_bits_made_lower(a: U64x2) -> U64x2 {
        U64x2::from(U8x16::from(a).shift_bytes_right::<8>())
    }

    #[inline(always)]
    fn lower_bits_made_upper(a: U64x2) -> U64x2 {
        U64x2::from(U8x16::from(a).shift_bytes_left::<8>())
    }

    #[inline(always)]
    pub(crate) fn mul_wide(a: u128, b: u128) -> (u128, u128) {
        // The constants determine
        // which 64-bit half of lhs and rhs we want to use for this carry-less multiplication.
        // See https://www.felixcloutier.com/x86/pclmulqdq#tbl-4-13 and
        // algorithm 2 on page 12 of https://is.gd/tOd246
        let a: U64x2 = bytemuck::cast(a);
        let b: U64x2 = bytemuck::cast(b);
        let c = a.carryless_mul::<true, true>(b);
        let d = a.carryless_mul::<false, false>(b);
        // CLMUL(lower bits of a ^ upper bits of a, lower bits of b ^ upper bits of b)
        let e = (a ^ upper_bits_made_lower(a))
            .carryless_mul::<false, false>(b ^ upper_bits_made_lower(b));
        let product_upper_half =
            c ^ upper_bits_made_lower(c) ^ upper_bits_made_lower(d) ^ upper_bits_made_lower(e);
        let product_lower_half =
            d ^ lower_bits_made_upper(d) ^ lower_bits_made_upper(c) ^ lower_bits_made_upper(e);
        (
            bytemuck::cast(product_upper_half),
            bytemuck::cast(product_lower_half),
        )
    }

    #[inline(always)]
    pub(crate) fn reduce(upper: u128, lower: u128) -> u128 {
        // Page 15 of https://is.gd/tOd246
        // Reduce the polynomial represented in bits over x^128 + x^7 + x^2 + x + 1
        // TODO: we should probably do this in vector operations...
        fn sep(x: u128) -> (u64, u64) {
            // (high, low)
            ((x >> 64) as u64, x as u64)
        }
        fn join(u: u64, l: u64) -> u128 {
            ((u as u128) << 64) | (l as u128)
        }

        let (x3, x2) = sep(upper);
        let (x1, x0) = sep(lower);
        let a = x3 >> 63;
        let b = x3 >> 62;
        let c = x3 >> 57;
        let d = x2 ^ a ^ b ^ c;
        let (e1, e0) = sep(join(x3, d) << 1);
        let (f1, f0) = sep(join(x3, d) << 2);
        let (g1, g0) = sep(join(x3, d) << 7);
        let h1 = x3 ^ e1 ^ f1 ^ g1;
        let h0 = d ^ e0 ^ f0 ^ g0;
        join(x1 ^ h1, x0 ^ h0)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use proptest::prelude::*;
        use swanky_field::polynomial::Polynomial;

        fn poly_from_upper_and_lower_128(upper: u128, lower: u128) -> Polynomial<F2> {
            let mut out = Polynomial {
                constant: F2::try_from((lower & 1) as u8).unwrap(),
                coefficients: Default::default(),
            };
            for shift in 1..128 {
                out.coefficients
                    .push(F2::try_from(((lower >> shift) & 1) as u8).unwrap());
            }
            for shift in 0..128 {
                out.coefficients
                    .push(F2::try_from(((upper >> shift) & 1) as u8).unwrap());
            }
            out
        }

        fn poly_from_128(x: u128) -> Polynomial<F2> {
            let x = F128b(x).decompose();
            Polynomial {
                constant: x[0],
                coefficients: x[1..].iter().cloned().collect(),
            }
        }

        proptest! {
            #[test]
            fn unreduced_multiply(a in any::<u128>(), b in any::<u128>()) {
                let a_poly = poly_from_128(a);
                let b_poly = poly_from_128(b);
                let (upper, lower) = mul_wide(a, b);
                let mut product = a_poly;
                product *= &b_poly;
                assert_eq!(
                    poly_from_upper_and_lower_128(upper, lower),
                    product
                );
            }
        }

        fn assert_div_mod(
            poly: &Polynomial<F2>,
            quotient: &Polynomial<F2>,
            remainder: &Polynomial<F2>,
        ) {
            let mut tmp = quotient.clone();
            tmp *= &F128b::polynomial_modulus();
            tmp += remainder;
            assert_eq!(poly, &tmp);
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(
                std::env::var("PROPTEST_CASES")
                    .map(|x| x.parse().expect("PROPTEST_CASES is a number"))
                    .unwrap_or(15)
            ))]
            #[test]
            fn reduction(upper in any::<u128>(), lower in any::<u128>()) {
                let poly = poly_from_upper_and_lower_128(upper, lower);
                let reduced = reduce(upper, lower);
                let (poly_quotient, poly_reduced) = poly.divmod(&F128b::polynomial_modulus());
                assert_div_mod(&poly, &poly_quotient, &poly_reduced);
                assert_eq!(poly_from_128(reduced), poly_reduced);
            }
        }
    }
}

impl<'a> MulAssign<&'a F128b> for F128b {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a F128b) {
        let (upper, lower) = multiply::mul_wide(self.0, rhs.0);
        self.0 = multiply::reduce(upper, lower);
    }
}

impl FiniteRing for F128b {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        F128b(u128::from_le_bytes(*x))
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes[..]);
        F128b(u128::from_le_bytes(bytes))
    }

    const ZERO: Self = F128b(0);
    const ONE: Self = F128b(1);
}

impl CanonicalSerialize for F128b {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(F128b(u128::from_le_bytes(*bytes.as_ref())))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }
}

impl FiniteField for F128b {
    type PrimeField = F2;

    const GENERATOR: Self = F128b(2);

    fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
        let mut coefficients = vec![F2::ZERO; 128];
        coefficients[128 - 1] = F2::ONE;
        coefficients[7 - 1] = F2::ONE;
        coefficients[2 - 1] = F2::ONE;
        coefficients[1 - 1] = F2::ONE;
        Polynomial {
            constant: F2::ONE,
            coefficients,
        }
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U128;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        swanky_field::standard_bit_decomposition(self.0)
    }

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time(u128::MAX - 1)
    }
}

impl From<F2> for F128b {
    #[inline]
    fn from(x: F2) -> Self {
        Self(x.0 as u128)
    }
}
impl Mul<F128b> for F2 {
    type Output = F128b;
    #[inline]
    fn mul(self, x: F128b) -> F128b {
        F128b::conditional_select(&F128b::ZERO, &x, self.ct_eq(&F2::ONE))
    }
}

impl IsSubRingOf<F128b> for F2 {}
impl IsSubFieldOf<F128b> for F2 {
    type DegreeModulo = generic_array::typenum::U128;
    fn decompose_superfield(fe: &F128b) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from_iter(
            (0..128).map(|shift| F2::try_from(((fe.0 >> shift) & 1) as u8).unwrap()),
        )
    }

    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> F128b {
        let mut out = 0;
        for x in components.iter().rev() {
            out <<= 1;
            out |= u128::from(u8::from(*x));
        }
        F128b(out)
    }
}

swanky_field::field_ops!(F128b);

#[cfg(test)]
mod tests {
    use super::F128b;
    swanky_field_test::test_field!(test_field, F128b);
}

#[test]
fn test_generator() {
    let n = u128::MAX;
    let prime_factors: Vec<u128> = vec![67280421310721, 274177, 6700417, 641, 65537, 257, 17, 5, 3];
    let x = F128b::GENERATOR;
    for p in prime_factors.iter() {
        let p = *p;
        assert_ne!(F128b::ONE, x.pow(n / p));
    }
}
