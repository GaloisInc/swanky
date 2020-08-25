use crate::field::{f2::F2, polynomial::Polynomial, FiniteField};
use generic_array::GenericArray;
use rand_core::RngCore;
use smallvec::smallvec;
use std::{
    convert::TryFrom,
    iter::FromIterator,
    ops::{AddAssign, MulAssign, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// An element of the finite field $\textsf{GF}(2^{128})$ reduced over $x^{128} + x^{127} + x^{126} + x^{121} + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We use a u128 since Rust will pass it in registers, unlike a __m128i
pub struct Gf128(pub(crate) u128);

// We use the same GF from Polyval. See https://tools.ietf.org/html/rfc8452#appendix-A for more info

impl ConstantTimeEq for Gf128 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for Gf128 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf128(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a Gf128> for Gf128 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a Gf128) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a Gf128> for Gf128 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a Gf128) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}
impl<'a> MulAssign<&'a Gf128> for Gf128 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a Gf128) {
        use std::arch::x86_64::*;
        // This function is based on https://github.com/RustCrypto/universal-hashes/blob/663295cfcc4a0aa263fc63589953d5cc59856a22/polyval/src/field/pclmulqdq.rs
        // The original code is MIT/Apache 2.0 dual-licensed.
        const MASK: u128 = 1 << 127 | 1 << 126 | 1 << 121 | 1;

        /// Fast reduction modulo x^128 + x^127 + x^126 +x^121 + 1 (Gueron 2012)
        /// Algorithm 4: "Montgomery reduction"
        ///
        /// See: <https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf>
        unsafe fn reduce(x: __m128i) -> __m128i {
            // `_mm_loadu_si128` performs an unaligned load
            // (`u128` is not necessarily aligned to 16-bytes)
            #[allow(clippy::cast_ptr_alignment)]
            let mask = _mm_loadu_si128(&MASK as *const u128 as *const __m128i);

            // pclmulqdq
            let a = _mm_clmulepi64_si128(mask, x, 0x01);

            // pshufd, pxor
            let b = _mm_xor_si128(_mm_shuffle_epi32(x, 0x4e), a);

            // pclmulqdq
            let c = _mm_clmulepi64_si128(mask, b, 0x01);

            // pshufd, pxor
            _mm_xor_si128(_mm_shuffle_epi32(b, 0x4e), c)
        }
        unsafe {
            let lhs = _mm_loadu_si128(&self.0 as *const _ as *const __m128i);
            let rhs = _mm_loadu_si128(&rhs.0 as *const _ as *const __m128i);
            // pclmulqdq
            let t1 = _mm_clmulepi64_si128(lhs, rhs, 0x00);

            // pclmulqdq
            let t2 = _mm_clmulepi64_si128(lhs, rhs, 0x01);

            // pclmulqdq
            let t3 = _mm_clmulepi64_si128(lhs, rhs, 0x10);

            // pclmulqdq
            let t4 = _mm_clmulepi64_si128(lhs, rhs, 0x11);

            // pxor
            let t5 = _mm_xor_si128(t2, t3);

            // psrldq, pxor
            let t6 = _mm_xor_si128(t4, _mm_bsrli_si128(t5, 8));

            // pslldq, pxor
            let t7 = _mm_xor_si128(t1, _mm_bslli_si128(t5, 8));

            // reduce, pxor
            let out = _mm_xor_si128(t6, reduce(t7));
            _mm_storeu_si128(&mut self.0 as *mut _ as *mut __m128i, out);
        }
    }
}

/// An error with no inhabitants. Gf128 cannot fail to deserialize.
#[derive(Clone, Copy, Debug)]
pub enum Gf128BytesDeserializationCannotFail {}
impl std::fmt::Display for Gf128BytesDeserializationCannotFail {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        unreachable!("Self has no values that inhabit it")
    }
}
impl std::error::Error for Gf128BytesDeserializationCannotFail {}

impl FiniteField for Gf128 {
    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = Gf128BytesDeserializationCannotFail;

    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(Gf128(u128::from_le_bytes(*bytes.as_ref())))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }

    type PrimeField = F2;
    type PolynomialFormNumCoefficients = generic_array::typenum::U128;

    fn from_polynomial_coefficients(
        coeff: GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients>,
    ) -> Self {
        Gf128(coeff.iter().enumerate().fold(0u128, |acu, (idx, value)| {
            acu | ((u8::from(*value) as u128) << ((127 - idx) as u128))
        })) * Gf128(1<<127).inverse()
    }

    fn to_polynomial_coefficients(
        &self,
    ) -> GenericArray<Self::PrimeField, Self::PolynomialFormNumCoefficients> {
        let out = self * Gf128(1<<127);
        GenericArray::from_iter(
            (0..128).map(|idx| F2::try_from(((out.0 >> (127 - idx)) & 0b1) as u8).unwrap()),
        )
    }

    fn reduce_multiplication_over() -> Polynomial<Self::PrimeField> {
        let mut coefficients = smallvec![F2::zero(); 128];
        coefficients[128 - 1] = F2::one();
        coefficients[127 - 1] = F2::one();
        coefficients[126 - 1] = F2::one();
        coefficients[121 - 1] = F2::one();
        Polynomial {
            constant: F2::one(),
            coefficients,
        }
    }

    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes[..]);
        Gf128(u128::from_le_bytes(bytes))
    }

    const MULTIPLICATIVE_GROUP_ORDER: u128 = u128::max_value();

    fn generator() -> Self {
        Gf128(1)
    }

    fn zero() -> Self {
        Gf128(0)
    }

    fn one() -> Self {
        Gf128(1 << 127 | 1 << 126 | 1 << 121 | 1)
    }
}

#[test]
fn rfc_8542_test_vector() {
    let a = Gf128(0x66e94bd4ef8a2c3b884cfa59ca342b2e);
    let b = Gf128(0xff000000000000000000000000000000);
    let product = a * b;
    assert_eq!(product, Gf128(0x37856175e9dc9df26ebc6d6171aa0ae9));
}

field_ops!(Gf128);

#[cfg(test)]
test_field!(test_gf128, Gf128);

#[test]
fn test_generator() {
    let n = Gf128::MULTIPLICATIVE_GROUP_ORDER;
    let prime_factors: Vec<u128> = vec![67280421310721, 274177, 6700417, 641, 65537, 257, 17, 5, 3];
    let x = Gf128::generator();
    for p in prime_factors.iter() {
        let p = *p;
        assert_ne!(Gf128::one(), x.pow(n / p));
    }
}
