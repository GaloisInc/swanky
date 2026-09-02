use crate::F2;
use generic_array::GenericArray;
use rand::Rng;
use vectoreyes::U8x32;
use std::iter::FromIterator;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};

#[cfg(test)]
use swanky_polynomial::Polynomial;

/// An element of the finite field $\textsf{GF}(2^{256})$ reduced over $x^{256} + x^{10} + x^5 + x^2 + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We use a pair of u128 limbs, least-significant first: limb 0 holds the coefficients of $x^0$
// through $x^{127}$ and limb 1 holds $x^{128}$ through $x^{255}$. Unlike `F128b`, there's no
// primitive Rust will pass in registers at this width, so this is just an array.
pub struct F256b(pub(crate) [u128; 2]);

impl F256b {
    /// Extract the least-significant bit from a `F256b` value.
    pub fn lsb(self) -> F2 {
        F2::from((self.0[0] & 1) != 0)
    }
}

/// Return the reduction polynomial for the field `F256b`.
#[cfg(test)]
#[allow(clippy::eq_op)]
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
        debug_assert!(0 < N && N < 128);
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

        /// A [`proptest`] strategy for a full-width 256-bit value.
        //
        // NOTE: This deliberately does not go through `swanky_field_test::arbitrary_ring`, which is
        // built on `from_uniform_bytes` and therefore only ever sets the lower 128 bits.
        fn any_256() -> impl Strategy<Value = [u128; 2]> {
            (any::<u128>(), any::<u128>()).prop_map(|(lo, hi)| [lo, hi])
        }

        fn poly_from_256(x: [u128; 2]) -> Polynomial<F2> {
            let x = F256b(x).decompose();
            Polynomial {
                constant: x[0],
                coefficients: x[1..].to_vec(),
            }
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

        /// Reference carry-less multiply, as a polynomial product over `F2`.
        //
        // Unlike `F128b`, there's no wider CLMUL primitive available to check against, so the
        // reference here is schoolbook polynomial multiplication.
        fn clmul_ref(a: [u128; 2], b: [u128; 2]) -> Polynomial<F2> {
            let mut out = poly_from_256(a);
            out *= &poly_from_256(b);
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

        /// Ground-truth vectors generated with an independent Python model of GF(2) polynomial
        /// arithmetic modulo $x^{256} + x^{10} + x^5 + x^2 + 1$.
        mod known_values {
            pub(super) const A: [u128; 2] = [
                0xf26047d69c0ebfae46b4734dd119ac50,
                0x05394e05d22ba8695cb0b766bf32d941,
            ];
            pub(super) const B: [u128; 2] = [
                0xd56b323216aad95a900b8408f8cc89ba,
                0x044875deececd1bf5a26e75489d75e6e,
            ];
            pub(super) const CLMUL_LO: [u128; 2] = [
                0x16a33f77786dfb6168e5b728f9a18d20,
                0x3c3e5b17fcb82f341cd599591ce7e01d,
            ];
            pub(super) const CLMUL_HI: [u128; 2] = [
                0x788f5becabb19475eccc03996311fb65,
                0x0015830961b33aec8ba73708b5cbac46,
            ];
            /// `A * B`, i.e. `clmul` followed by `reduce`.
            pub(super) const PRODUCT: [u128; 2] = [
                0xa095c412cd7967cd9e97ac7433256371,
                0x68c19091e14b11d551d4b1b2e9c66c6f,
            ];
            /// The multiplicative inverse of `A`.
            pub(super) const A_INVERSE: [u128; 2] = [
                0xe932b176dfa02531f17343891af36c90,
                0xda9a170d37792f6b6d9dbf923c2845fa,
            ];
            /// An upper half chosen so that reduction needs the *second* fold pass: bits 255, 254
            /// and 250 all overflow when shifted left by 10.
            pub(super) const FOLD_HI: [u128; 2] = [
                0x00000000000000000000000000000001,
                0xc4000000000000000000000000000000,
            ];
            pub(super) const FOLD_HI_REDUCED: [u128; 2] = [
                0x000000000000000000000000000c4662,
                0x54000000000000000000000000000000,
            ];
        }

        #[test]
        fn shl_matches_bitwise_reference() {
            fn shl_ref(x: [u128; 2], n: u32) -> ([u128; 2], u128) {
                let mut out = [0u128; 2];
                let mut over = 0u128;
                for i in 0..256usize {
                    if (x[i / 128] >> (i % 128)) & 1 == 1 {
                        let j = i + n as usize;
                        if j < 256 {
                            out[j / 128] |= 1 << (j % 128);
                        } else {
                            over |= 1 << (j - 256);
                        }
                    }
                }
                (out, over)
            }

            // The reduction only ever shifts by 2, 5 and 10, but check the boundaries too.
            for x in [
                [0u128, 0u128],
                [u128::MAX, u128::MAX],
                [1, 1 << 127],
                known_values::A,
                known_values::B,
            ] {
                assert_eq!(shl::<1>(x), shl_ref(x, 1), "n=1, x={x:x?}");
                assert_eq!(shl::<2>(x), shl_ref(x, 2), "n=2, x={x:x?}");
                assert_eq!(shl::<5>(x), shl_ref(x, 5), "n=5, x={x:x?}");
                assert_eq!(shl::<10>(x), shl_ref(x, 10), "n=10, x={x:x?}");
                assert_eq!(shl::<127>(x), shl_ref(x, 127), "n=127, x={x:x?}");
            }
        }

        #[test]
        fn carryless_mul_matches_known_value() {
            assert_eq!(
                clmul(known_values::A, known_values::B),
                (known_values::CLMUL_HI, known_values::CLMUL_LO)
            );
        }

        #[test]
        fn reduce_matches_known_value() {
            assert_eq!(
                reduce(known_values::FOLD_HI, [0, 0]),
                known_values::FOLD_HI_REDUCED
            );
        }

        /// `clmul` and `reduce` composed, which is what [`MulAssign`] actually runs.
        #[test]
        fn mul_matches_known_value() {
            assert_eq!(
                F256b(known_values::A) * F256b(known_values::B),
                F256b(known_values::PRODUCT)
            );
        }

        #[test]
        fn inverse_matches_known_value() {
            assert_eq!(
                F256b(known_values::A).inverse(),
                F256b(known_values::A_INVERSE)
            );
        }

        /// The defining relation of the modulus: $x^{256} = x^{10} + x^5 + x^2 + 1$.
        #[test]
        fn reduce_encodes_the_modulus() {
            assert_eq!(
                reduce([1, 0], [0, 0]),
                [(1 << 10) | (1 << 5) | (1 << 2) | 1, 0]
            );
        }

        proptest! {
            #[test]
            fn test_carryless_mul_256bit(a in any_256(), b in any_256()) {
                let (hi, lo) = clmul(a, b);
                prop_assert_eq!(poly_from_upper_and_lower_256(hi, lo), clmul_ref(a, b));
            }

            #[test]
            fn test_reduce(upper in any_256(), lower in any_256()) {
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

impl From<U8x32> for F256b {
    fn from(value: U8x32) -> Self {
        Self(bytemuck::cast(value))
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
    use generic_array::{GenericArray, typenum::U256};
    use proptest::prelude::*;
    use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
    swanky_field_test::test_field!(test_field, F256b, crate::f256b::polynomial_modulus_f256b);

    /// A full-width [`F256b`] strategy.
    //
    // NOTE: `swanky_field_test::arbitrary_ring` (and therefore everything inside `test_field!`) is
    // built on `from_uniform_bytes`, which can only fill the lower 128 bits of this field. These
    // tests use a 32-byte strategy so that the upper limb is actually exercised.
    fn any_f256b() -> impl Strategy<Value = F256b> {
        (any::<u128>(), any::<u128>()).prop_map(|(lo, hi)| F256b([lo, hi]))
    }

    proptest! {
        #[test]
        fn lsb_works(lo in any::<u128>(), hi in any::<u128>()) {
            prop_assert_eq!(F256b([lo, hi]).lsb(), F2::from((lo & 1) != 0));
        }
    }

    proptest! {
        /// Multiplication of full-width operands is associative and distributes over addition.
        //
        // `test_field!` checks these too, but only over the lower half of the field.
        #[test]
        fn full_width_arithmetic_works(
            a in any_f256b(),
            b in any_f256b(),
            c in any_f256b(),
        ) {
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * (b + c), a * b + a * c);
            prop_assert_eq!(a * F256b::ONE, a);
            prop_assert_eq!(a * F256b::ZERO, F256b::ZERO);
        }
    }

    proptest! {
        /// Every nonzero full-width element has a multiplicative inverse.
        #[test]
        fn full_width_inverse_works(a in any_f256b()) {
            prop_assume!(a != F256b::ZERO);
            prop_assert_eq!(a * a.inverse(), F256b::ONE);
        }
    }

    // The remaining tests cover the `F2` <-> `F256b` bit basis, which is what `schmivitz` uses to
    // lift its `[F8b; tau]` VOLE tags into the big field (see 256BIT_PLAN.md, Phase 0, Option A).
    // The protocol only needs this map to be an `F2`-linear bijection.

    proptest! {
        #[test]
        fn decompose_then_form_works(original in any_f256b()) {
            let composed: F256b = F2::form_superfield(&F2::decompose_superfield(&original));
            prop_assert_eq!(original, composed);
        }
    }

    proptest! {
        #[test]
        fn form_then_decompose_works(bits in prop::collection::vec(any::<bool>(), 256)) {
            let bits: GenericArray<F2, U256> =
                bits.into_iter().map(F2::from).collect();
            let lifted: F256b = F2::form_superfield(&bits);
            prop_assert_eq!(bits, F2::decompose_superfield(&lifted));
        }
    }

    proptest! {
        /// The lift is `F2`-linear, which is the property the VOLE relation `q = u * Delta + v`
        /// depends on.
        #[test]
        fn form_superfield_is_f2_linear(
            a in prop::collection::vec(any::<bool>(), 256),
            b in prop::collection::vec(any::<bool>(), 256),
        ) {
            let sum: GenericArray<F2, U256> = a
                .iter()
                .zip(b.iter())
                .map(|(x, y)| F2::from(x ^ y))
                .collect();
            let a: GenericArray<F2, U256> = a.into_iter().map(F2::from).collect();
            let b: GenericArray<F2, U256> = b.into_iter().map(F2::from).collect();

            let lifted_sum: F256b = F2::form_superfield(&sum);
            let (lift_a, lift_b): (F256b, F256b) =
                (F2::form_superfield(&a), F2::form_superfield(&b));
            prop_assert_eq!(lifted_sum, lift_a + lift_b);
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

    // 2^256 - 1 = (2^1 - 1)(2^1 + 1)(2^2 + 1)(2^4 + 1)(2^8 + 1)(2^16 + 1)(2^32 + 1)(2^64 + 1)(2^128 + 1),
    // fully factored (the last two factors are the known factorizations of F6 and F7).
    let prime_factors: Vec<u128> = vec![
        5704689200685129054721,
        59649589127497217,
        67280421310721,
        274177,
        6700417,
        641,
        65537,
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
