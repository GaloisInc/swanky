use crate::F2;
use generic_array::GenericArray;
use rand::Rng;
use std::iter::FromIterator;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use vectoreyes::U8x32;

#[cfg(test)]
use swanky_polynomial::Polynomial;

/// An element of the finite field $\textsf{GF}(2^{256})$ reduced over $x^{256} + x^{10} + x^5 + x^2 + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We represent a 256-bit value using a pair of u128 in little-endian order. I.e., the coefficients
// are stored as `[[x^0, ..., x^127], [x^128, ..., x^255]]`.
//
// We could instead use U64x4 (__m256i on x86), but this would run into issues implementing
// FiniteRing, since it has no const constructor to generate ONE and GENERATOR. Using transmute
// would be possible, but unsafe.
pub struct F256b(pub(crate) [u128; 2]);

impl F256b {
    /// Extract the least-significant bit from a `F256b` value.
    pub fn lsb(self) -> F2 {
        F2::from((self.0[0] & 1) != 0)
    }
}

/// Return the reduction polynomial for the field `F256b`.
#[cfg(test)]
fn polynomial_modulus_f256b() -> Polynomial<<F256b as FiniteField>::PrimeField> {
    let mut coefficients = vec![F2::ZERO; 256];
    coefficients[256 - 1] = F2::ONE;
    coefficients[10 - 1] = F2::ONE;
    coefficients[5 - 1] = F2::ONE;
    coefficients[2 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

impl ConstantTimeEq for F256b {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0]) & self.0[1].ct_eq(&other.0[1])
    }
}
impl ConditionallySelectable for F256b {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F256b([
            u128::conditional_select(&a.0[0], &b.0[0], choice),
            u128::conditional_select(&a.0[1], &b.0[1], choice),
        ])
    }
}

impl<'a> AddAssign<&'a F256b> for F256b {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &'a F256b) {
        self.0[0] ^= rhs.0[0];
        self.0[1] ^= rhs.0[1];
    }
}
impl<'a> SubAssign<&'a F256b> for F256b {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: &'a F256b) {
        // The additive inverse of GF(2^256) is the identity
        *self += rhs;
    }
}

/// Internal implementation details of the [`AssignMul::assign_mul`] implementation for `F256b`.
//
// NOTE This contains no architecture-specific code: the only such code is the 128-bit carry-less
// multiply, which is reused from `F128b` (where it is already encapsulated behind `vectoreyes` and
// `move_to_vectoreyes`).
mod multiplication {
    use crate::f128b::multiplication::clmul as clmul_128;

    /// Shift a 256-bit value left by the specified (const) number of bits, as if it were a single
    /// string of bits.
    ///
    /// Returns the low 256 bits of the result along with the `N` bits shifted off the top.
    #[inline(always)]
    fn shl<const N: u32>(x: [u128; 2]) -> ([u128; 2], u128) {
        // NOTE: This check is free at run time. It fires at compile time, since `N` is a const generic.
        assert!(0 < N && N < 128);
        (
            [x[0] << N, (x[1] << N) ^ (x[0] >> (128 - N))],
            x[1] >> (128 - N),
        )
    }

    // Schoolbook multiplication, mirroring `F128b`'s `clmul` one level up: the same four partial
    // products and the same shared-term trick, but over 128-bit limbs instead of 64-bit ones.
    //
    /// Multiply `a` and `b`, interpreted as degree-255 Boolean polynomials. The result has degree
    /// 510, so it is returned in the form of 2 limb pairs containing the upper and lower bits, in
    /// that order: (hi, lo) = a * b
    ///
    /// TODO: This is based on the `clmul` implementation for `F128b`, where the selection of
    /// schoolbook multiplication, rather than Karatsuba was based on measured performance
    /// characteristics. There's a strong possibility those characteristics would differ in the
    /// `F256b` case. We should test this and change the implementation accordingly.
    #[inline(always)]
    pub(crate) fn clmul(a: [u128; 2], b: [u128; 2]) -> ([u128; 2], [u128; 2]) {
        // a = [A1 : A0], b = [B1 : B0]
        let (c1, c0) = clmul_128(a[0], b[0]); // [C1 : C0] = A0 • B0
        let (d1, d0) = clmul_128(a[1], b[1]); // [D1 : D0] = A1 • B1
        let (e1, e0) = clmul_128(a[0], b[1]); // [E1 : E0] = A0 • B1
        let (f1, f0) = clmul_128(a[1], b[0]); // [F1 : F0] = A1 • B0

        let (ef1, ef0) = (e1 ^ f1, e0 ^ f0); // common term: [F1 ⊕ E1 : F0 ⊕ E0]

        // [D1 : F1 ⊕ E1 ⊕ D0 : F0 ⊕ E0 ⊕ C1 : C0]
        ([d0 ^ ef1, d1], [c0, c1 ^ ef0])
    }

    /// Fold a 256-bit value down by one power of $x^{256}$, i.e. multiply it by
    /// $x^{10} + x^5 + x^2 + 1$.
    ///
    /// The product has degree at most 265, so it is returned as the low 256 bits along with the
    /// (at most 10) bits that overflowed.
    #[inline(always)]
    fn fold(x: [u128; 2]) -> ([u128; 2], u128) {
        let (a, a_over) = shl::<2>(x); // [A1 : A0] = X << 2
        let (b, b_over) = shl::<5>(x); // [B1 : B0] = X << 5
        let (c, c_over) = shl::<10>(x); // [C1 : C0] = X << 10

        (
            [x[0] ^ a[0] ^ b[0] ^ c[0], x[1] ^ a[1] ^ b[1] ^ c[1]],
            a_over ^ b_over ^ c_over,
        )
    }

    /// Reduce the polynomial represented in bits over x^256 + x^10 + x^5 + x^2 + 1
    #[inline(always)]
    pub(crate) fn reduce(hi: [u128; 2], lo: [u128; 2]) -> [u128; 2] {
        // Since x^256 ≡ x^10 + x^5 + x^2 + 1, folding the upper half down leaves at most 10 bits
        // sticking out past x^255...
        let (r, over) = fold(hi);
        // ...and folding those down can't overflow again, because 9 + 10 < 256.
        let (s, over2) = fold([over, 0]);
        debug_assert_eq!(over2, 0);

        [lo[0] ^ r[0] ^ s[0], lo[1] ^ r[1] ^ s[1]]
    }

    #[cfg(test)]
    mod test {
        use super::{super::polynomial_modulus_f256b, *};
        use crate::{F2, F256b};
        use proptest::{prelude::*, prop_assert_eq, test_runner::TestCaseError};
        use swanky_field::FiniteField;
        use swanky_polynomial::Polynomial;

        fn poly_from_256(x: [u128; 2]) -> Polynomial<F2> {
            let x = F256b(x).decompose();
            Polynomial {
                constant: x[0],
                coefficients: x[1..].to_vec(),
            }
        }

        // Unlike `F128b`, there's no wider CLMUL primitive available to check against, so the
        // reference here is schoolbook polynomial multiplication.
        fn clmul_ref(a: [u128; 2], b: [u128; 2]) -> Polynomial<F2> {
            let mut out = poly_from_256(a);
            out *= &poly_from_256(b);
            out
        }

        fn poly_from_upper_and_lower_256(upper: [u128; 2], lower: [u128; 2]) -> Polynomial<F2> {
            fn bit(x: [u128; 2], i: usize) -> F2 {
                F2::from((x[i / 128] >> (i % 128)) & 1 == 1)
            }

            let mut out = Polynomial {
                constant: bit(lower, 0),
                coefficients: Vec::with_capacity(511),
            };
            for shift in 1..256 {
                out.coefficients.push(bit(lower, shift));
            }
            for shift in 0..256 {
                out.coefficients.push(bit(upper, shift));
            }
            out
        }

        fn reduce_ref(hi: [u128; 2], lo: [u128; 2]) -> Result<Polynomial<F2>, TestCaseError> {
            fn assert_div_mod(
                poly: &Polynomial<F2>,
                quotient: &Polynomial<F2>,
                remainder: &Polynomial<F2>,
            ) -> Result<(), TestCaseError> {
                let mut tmp = quotient.clone();
                tmp *= &polynomial_modulus_f256b();
                tmp += remainder;
                prop_assert_eq!(poly, &tmp);
                Ok(())
            }

            let poly = poly_from_upper_and_lower_256(hi, lo);
            let (poly_quotient, poly_reduced) = poly.divmod(&polynomial_modulus_f256b());
            assert_div_mod(&poly, &poly_quotient, &poly_reduced)?;

            Ok(poly_reduced)
        }

        // NOTE: `swanky_field_test::arbitrary_ring` (and therefore everything inside `test_field!`) is
        // built on `from_uniform_bytes`, which can only fill the lower 128 bits of this field. These
        // tests use a `[u128; 2]` strategy so that the upper limb is actually exercised.
        proptest! {
            #[test]
            fn test_carryless_mul_256bit(a: [u128; 2], b: [u128; 2]) {
                let (hi, lo) = clmul(a, b);
                prop_assert_eq!(poly_from_upper_and_lower_256(hi, lo), clmul_ref(a, b));
            }

            #[test]
            fn test_reduce(upper: [u128; 2], lower: [u128; 2]) {
                let poly_reduced = reduce_ref(upper, lower)?;
                prop_assert_eq!(poly_from_256(reduce(upper, lower)), poly_reduced);
            }
        }
    }
}

impl<'a> MulAssign<&'a F256b> for F256b {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a F256b) {
        use multiplication::*;
        let (hi, lo) = clmul(self.0, rhs.0);
        self.0 = reduce(hi, lo);
    }
}

impl FiniteRing for F256b {
    // FIXME: FiniteRing does not nicely support fields larger than 128-bit nicely, since
    // from_uniform_bytes takes at most 128-bits of randomness. We should decide how to fix this.
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        // NOTE: The trait fixes this input at 16 bytes, which is only half the width of this field,
        // so the upper limb is left zero. The result is therefore *not* uniform over `F256b`, and
        // this must not be used to derive Fiat-Shamir challenges: use `from_bytes` with 32 bytes of
        // randomness instead.
        F256b([u128::from_le_bytes(*x), 0])
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes[..]);
        F256b([
            u128::from_le_bytes(bytes[..16].try_into().unwrap()),
            u128::from_le_bytes(bytes[16..].try_into().unwrap()),
        ])
    }

    const ZERO: Self = F256b([0, 0]);
    const ONE: Self = F256b([1, 0]);
}

impl CanonicalSerialize for F256b {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U32;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        // These unwraps are safe because `ByteReprLen` fixes the length at 32.
        Ok(F256b([
            u128::from_le_bytes(bytes[..16].try_into().unwrap()),
            u128::from_le_bytes(bytes[16..].try_into().unwrap()),
        ]))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        let mut out = GenericArray::default();
        out[..16].copy_from_slice(&self.0[0].to_le_bytes());
        out[16..].copy_from_slice(&self.0[1].to_le_bytes());
        out
    }
}

impl FiniteField for F256b {
    type PrimeField = F2;

    const GENERATOR: Self = F256b([2, 0]);

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U256;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        // `swanky_field::standard_bit_decomposition` only accepts a `u128`, so we walk the limbs.
        GenericArray::from_iter(
            (0..256).map(|shift| (self.0[shift / 128] >> (shift % 128)) & 1 == 1),
        )
    }

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        // By Fermat's little theorem, `self`'s inverse is `self^(2^256 - 2)`. `pow_var_time` takes
        // a `u128` exponent, which is too narrow, so we walk the addition chain implied by
        // `2^256 - 2 = 2 * (2^255 - 1)`: the loop maintains `acc = self^(2^k - 1)`.
        let mut acc = *self; // k = 1
        for _ in 1..255 {
            acc = acc * acc * *self;
        }
        acc * acc
    }
}

impl From<F2> for F256b {
    #[inline]
    fn from(x: F2) -> Self {
        Self([x.0 as u128, 0])
    }
}
impl Mul<F256b> for F2 {
    type Output = F256b;
    #[inline]
    fn mul(self, x: F256b) -> F256b {
        F256b::conditional_select(&F256b::ZERO, &x, self.ct_eq(&F2::ONE))
    }
}

impl From<U8x32> for F256b {
    fn from(value: U8x32) -> Self {
        Self(bytemuck::cast(value))
    }
}
impl From<F256b> for U8x32 {
    fn from(value: F256b) -> Self {
        bytemuck::cast(value.0)
    }
}

impl IsSubRingOf<F256b> for F2 {}
impl IsSubFieldOf<F256b> for F2 {
    type DegreeModulo = generic_array::typenum::U256;
    fn decompose_superfield(fe: &F256b) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from_iter(
            (0..256).map(|shift| {
                F2::try_from(((fe.0[shift / 128] >> (shift % 128)) & 1) as u8).unwrap()
            }),
        )
    }

    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> F256b {
        let mut out = [0u128; 2];
        for (i, x) in components.iter().enumerate() {
            out[i / 128] |= u128::from(u8::from(*x)) << (i % 128);
        }
        F256b(out)
    }
}

swanky_field::field_ops!(F256b);

#[cfg(test)]
mod tests {
    use crate::F2;

    use super::F256b;
    use proptest::prelude::*;
    swanky_field_test::test_field!(test_field, F256b, crate::f256b::polynomial_modulus_f256b);

    proptest! {
        #[test]
        fn lsb_works(input: [u128; 2]) {
            prop_assert_eq!(F256b(input).lsb(), F2::from((input[0] & 1) != 0));
        }
    }
}

/// Check that [`F256b::GENERATOR`] really does generate the multiplicative group.
//
// This mirrors `F128b`'s `test_generator`, but neither the group order `2^256 - 1` nor the
// cofactors `(2^256 - 1)/p` fit in a `u128`, so we can't use `FiniteRing::pow`. We use
// `crypto_bigint::U256` for the exponent arithmetic and a local square-and-multiply instead.
#[test]
fn test_generator() {
    use crypto_bigint::{NonZero, U256};
    use swanky_field::FiniteRing;

    let prime_factors: Vec<u128> = vec![
        5704689200685129054721,
        59649589127497217,
        67280421310721,
        6700417,
        274177,
        65537,
        641,
        257,
        17,
        5,
        3,
    ];

    let n = U256::MAX; // 2^256 - 1
    assert_eq!(
        prime_factors
            .iter()
            .fold(U256::ONE, |acc, p| acc.wrapping_mul(&U256::from_u128(*p))),
        n,
        "the listed prime factors don't multiply out to 2^256 - 1"
    );

    fn pow(x: F256b, e: &U256) -> F256b {
        let mut out = F256b::ONE;
        // Square-and-multiply, most significant bit first.
        for i in (0..e.bits_vartime()).rev() {
            out = out * out;
            if e.bit_vartime(i) {
                out *= x;
            }
        }
        out
    }

    let x = F256b::GENERATOR;
    assert_eq!(pow(x, &n), F256b::ONE, "generator is not in the group");
    for p in prime_factors.iter() {
        let cofactor = n.wrapping_div(&NonZero::new(U256::from_u128(*p)).unwrap());
        assert_ne!(
            F256b::ONE,
            pow(x, &cofactor),
            "generator has order dividing (2^256 - 1)/{p}"
        );
    }
}
