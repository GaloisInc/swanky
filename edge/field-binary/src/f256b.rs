use crate::F2;
use generic_array::GenericArray;
use rand::{Rng, SeedableRng};
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
    use vectoreyes::U8x32;

    // Algorithm 1 from page 12 of https://is.gd/tOd246
    //
    // The paper describes this as, "one iteration carry-less schoolbook" multiplication. In
    // comparison to Algorithm 2 ("one iteration carry-less Karatsuba"), this performed about 15%
    // better on x86_64 in benchmarks.
    //
    #[inline(always)]
    pub(crate) fn clmul(a: [u128; 2], b: [u128; 2]) -> ([u128; 2], [u128; 2]) {
        // a = [A1 : A0], b = [B1 : B0]
        let (c1, c0) = clmul_128(a[0], b[0]); // [C1 : C0] = A0 • B0
        let (d1, d0) = clmul_128(a[1], b[1]); // [D1 : D0] = A1 • B1
        let (e1, e0) = clmul_128(a[0], b[1]); // [E1 : E0] = A0 • B1
        let (f1, f0) = clmul_128(a[1], b[0]); // [F1 : F0] = A1 • B0

        let e: U8x32 = bytemuck::cast([e1, e0]);
        let f: U8x32 = bytemuck::cast([f1, f0]);

        // [D1 : F1 ⊕ E1 ⊕ D0 : F0 ⊕ E0 ⊕ C1 : C0]
        let [ef1, ef0]: [u128; 2] = bytemuck::cast(e ^ f); // common term: [F1 ⊕ E1 : F0 ⊕ E0]
        let lo = [d0 ^ ef1, d1];
        let hi = [c0, c1 ^ ef0];
        (lo, hi)
    }

    /// Shift a 256-bit value left by the specified (const) number of bits, as if it were a single
    /// string of bits.
    #[inline(always)]
    fn shl<const N: u32>(x: [u128; 2]) -> [u128; 2] {
        // NOTE: This check is free at run time. It fires at compile time, since `N` is a const generic.
        assert!(0 < N && N < 128);
        [x[0] << N, (x[1] << N) ^ (x[0] >> (128 - N))]
    }

    // Adapts algorithm (4) from page 15 of https://is.gd/tOd246 to the 256-bit case.
    // Reduce the polynomial represented in bits over x^256 + x^10 + x^5 + x^2 + 1
    #[inline(always)]
    pub(crate) fn reduce(hi: [u128; 2], lo: [u128; 2]) -> [u128; 2] {
        // [X3 : X2 : X1 : X0] = X
        let x1_x0: U8x32 = bytemuck::cast(lo);
        let x2 = hi[0];
        let x3 = hi[1];

        let a = x3 >> 126; // A = X3 >> (128 - 2)
        let b = x3 >> 123; // B = X3 >> (128 - 5)
        let c = x3 >> 118; // C = X3 >> (128 - 10)
        let d = x2 ^ a ^ b ^ c; // D = X2 + A + B + C

        let x3_d = [d, x3]; // [X3 : D] = [X3 : X2 ⊕ A ⊕ B ⊕ C]
        let e: U8x32 = bytemuck::cast(shl::<2>(x3_d)); // [E1 : E0] = [X3 : D] << 2
        let f: U8x32 = bytemuck::cast(shl::<5>(x3_d)); // [F1 : F0] = [X3 : D] << 5
        let g: U8x32 = bytemuck::cast(shl::<10>(x3_d)); // [G1 : G0] = [X3 : D] << 10

        // [H1 : H0] = [X3 ⊕ E1 ⊕ F1 ⊕ G1 : D ⊕ E0 ⊕ F0 ⊕ G0]
        let x3_d: U8x32 = bytemuck::cast(x3_d);
        let h = x3_d ^ e ^ f ^ g;
        bytemuck::cast(x1_x0 ^ h) // [X1 ⊕ H1 : X0 ⊕ H0]
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
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        // NOTE: The trait fixes this input at 16 bytes.Therefore we populate the full width of the
        // field element using ChaCha20.
        let mut seed = [0; 32];
        seed[0..16].copy_from_slice(x);
        // AES key scheduling is slower than ChaCha20
        // TODO: this is still quite slow.
        Self::random(&mut rand_chacha::ChaCha20Rng::from_seed(seed))
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
    use swanky_field_test::{arbitrary_ring, test_field};

    test_field! {
        test_field,
        F256b,
        crate::f256b::polynomial_modulus_f256b
    }

    proptest! {
        #[test]
        fn lsb_works(input in arbitrary_ring::<F256b>()) {
            prop_assert_eq!(input.lsb(), F2::from((input.0[0] & 1) != 0));
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
