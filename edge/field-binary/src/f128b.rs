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
use vectoreyes::{SimdBase, U8x16};

#[cfg(test)]
use swanky_polynomial::Polynomial;

/// An element of the finite field $\textsf{GF}(2^{128})$ reduced over $x^{128} + x^7 + x^2 + x + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We use a u128 since Rust will pass it in registers, unlike a __m128i
pub struct F128b(pub(crate) u128);

impl F128b {
    /// Extract the least-significant bit from a `F128b` value.
    pub fn lsb(self) -> F2 {
        F2::from((U8x16::from(self).extract::<0>() & 1) != 0)
    }
}

/// Return the reduction polynomial for the field `F128b`.
#[cfg(test)]
#[allow(clippy::eq_op)]
fn polynomial_modulus_f128b() -> Polynomial<<F128b as FiniteField>::PrimeField> {
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
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &'a F128b) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F128b> for F128b {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: &'a F128b) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}

// This module isolates the architecture specific code used for F128b MUL. Ideally, all of this can
// be moved to vectoreyes and this module removed. Besides pointing the calls to the functions here
// to vectoreyes instead, no other changes should be required to the `multiplication` module below.
#[macro_use]
mod move_to_vectoreyes {
    use vectoreyes::U64x2;

    /// Multiply either the high or low lanes of lhs and rhs, interpreted as degree-127 Boolean
    /// polynomials. The result has degree 255, so it is returned in the form of 2 u128s containing
    /// the upper and lower bits, in that order: (hi, lo) = lhs * rhs
    //
    // This function is the equivalent of F64x2::carryless_mul instantiated for a platform with
    // aarch64 neon extentions. Moving it to Vectoreyes should be straightforward.
    #[inline(always)]
    pub(crate) fn carryless_mul_64bit<const HI_RHS: bool, const HI_LHS: bool>(
        lhs: U64x2,
        rhs: U64x2,
    ) -> U64x2 {
        #[cfg(target_arch = "aarch64")]
        if std::cfg!(all(target_feature = "neon", target_feature = "aes")) {
            use vectoreyes::SimdBase;
            let x = if HI_LHS {
                lhs.as_array()[1]
            } else {
                lhs.as_array()[0]
            };
            let y = if HI_RHS {
                rhs.as_array()[1]
            } else {
                rhs.as_array()[0]
            };
            let z = unsafe { core::arch::aarch64::vmull_p64(x, y) };
            return U64x2::from_array([z as u64, (z >> 64) as u64]);
        }
        lhs.carryless_mul::<HI_RHS, HI_LHS>(rhs)
    }

    /// Shift a U64x2 right by the specified (literal) number of bits as if it were a single string
    /// of bits.
    //
    // In order to acheive the best performance on both x86_64 and aarch64, we need to perform
    // *algorithmically* different operations on the 2 architectures:
    // - aarch64: Here we have native 128-bit registers, so we just want to use the standard shift
    //   operator. This results in ~15% faster MULs, all other things being equal.
    // - x86_64: Here, we don't have native 128-bit registers, so we can achieve better performance
    //   by performing a series of lane-wise shifts on MMX registers. This results in ~22% faster
    //   MULs all else being equal.
    //
    // NOTE: This doesn't currently exist in vectoreyes, as far as I can tell. I think that's
    // because vectoreyes is focused on exposing *single MM instructions*. I don't think it's set
    // up to expose *algorithmically* different implementations of high-level functionalities on
    // different platforms, which is what we need here.
    macro_rules! shl {
        ($x:expr, lt64 $n:literal) => {{
            debug_assert!(0 <= $n && $n < 64);
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase;
                let lo = x.shift_left::<$n>(); // Shift each lane by n
                let carry = x.shift_right::<{ 64 - $n }>(); // Bits that should cross lanes
                let hi_carry = shl!(carry, 64); // Move carry into high lane
                lo ^ hi_carry
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) << $n)
        }};
        ($x:expr, 64) => {{
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase8;
                vectoreyes::U64x2::from(vectoreyes::U8x16::from(x).shift_bytes_left::<8>())
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) << 64)
        }};
        ($x:expr, gt64 $n:literal) => {{
            debug_assert!($n > 64);
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase;
                let lo = shl!(x, 64); // Move low bits into high lane
                lo.shift_left::<{ $n - 64 }>() // Shift high bits the rest of the way
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) << $n)
        }};
    }

    /// Shift a U64x2 right by the specified (literal) number of bits as if it were a single string
    /// of bits.
    //
    // NOTE: This mirrors shl. See the NOTE there for more info.
    macro_rules! srl {
        ($x:expr, lt64 $n:literal) => {{
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase;
                let hi = x.shift_right::<$n>(); // Shift each lane by n
                let carry = x.shift_left::<{ 64 - $n }>(); // Bits that should cross lanes
                let lo_carry = srl!(carry, 64); // Move carry into low lane
                hi ^ lo_carry
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) >> $n)
        }};
        ($x:expr, 64) => {{
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase8;
                vectoreyes::U64x2::from(vectoreyes::U8x16::from(x).shift_bytes_right::<8>())
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) >> 64)
        }};
        ($x:expr, gt64 $n:literal) => {{
            let x: vectoreyes::U64x2 = $x; // Fail if x isn't U64x2
            #[cfg(target_arch = "x86_64")]
            {
                use vectoreyes::SimdBase;
                let hi = srl!(x, 64); // Move high bits into low lane
                hi.shift_right::<{ $n - 64 }>() // Shift low bits the rest of the way
            }
            #[cfg(not(target_arch = "x86_64"))]
            bytemuck::cast::<_, vectoreyes::U64x2>(bytemuck::cast::<_, u128>(x) >> $n)
        }};
    }

    #[cfg(test)]
    mod tests {
        use proptest::prelude::*;
        use vectoreyes::U64x2;

        proptest! {
            #[test]
            fn test_shl(x: u128) {
                let x_v: U64x2 = bytemuck::cast(x);
                let x_1: u128 = bytemuck::cast(shl!(x_v, lt64 1));
                let x_5: u128 = bytemuck::cast(shl!(x_v, lt64 5));
                let x_63: u128 = bytemuck::cast(shl!(x_v, lt64 63));
                let x_64: u128 = bytemuck::cast(shl!(x_v, 64));
                let x_65: u128 = bytemuck::cast(shl!(x_v, gt64 65));
                let x_122: u128 = bytemuck::cast(shl!(x_v, gt64 122));
                let x_127: u128 = bytemuck::cast(shl!(x_v, gt64 127));
                prop_assert_eq!(x_1, x << 1);
                prop_assert_eq!(x_5, x << 5);
                prop_assert_eq!(x_63, x << 63);
                prop_assert_eq!(x_64, x << 64);
                prop_assert_eq!(x_65, x << 65);
                prop_assert_eq!(x_122, x << 122);
                prop_assert_eq!(x_127, x << 127);
            }

            #[test]
            fn test_srl(x: u128) {
                let x_v: U64x2 = bytemuck::cast(x);
                let x_1: u128 = bytemuck::cast(srl!(x_v, lt64 1));
                let x_5: u128 = bytemuck::cast(srl!(x_v, lt64 5));
                let x_63: u128 = bytemuck::cast(srl!(x_v, lt64 63));
                let x_64: u128 = bytemuck::cast(srl!(x_v, 64));
                let x_65: u128 = bytemuck::cast(srl!(x_v, gt64 65));
                let x_122: u128 = bytemuck::cast(srl!(x_v, gt64 122));
                let x_127: u128 = bytemuck::cast(srl!(x_v, gt64 127));
                prop_assert_eq!(x_1, x >> 1);
                prop_assert_eq!(x_5, x >> 5);
                prop_assert_eq!(x_63, x >> 63);
                prop_assert_eq!(x_64, x >> 64);
                prop_assert_eq!(x_65, x >> 65);
                prop_assert_eq!(x_122, x >> 122);
                prop_assert_eq!(x_127, x >> 127);
            }
        }
    }
}

/// Internal implementation details of the [`AssignMul::assign_mul`] implementation for `F128b`.
//
// NOTE This contains no architecture-specific code except what's encapsulated in functions from
// `vectoreyes` and `move_to_vectoreyes`.
//
// This is `pub(crate)` because `F256b` reuses `clmul`: a carry-less multiply is independent of the
// polynomial modulus, so the 256-bit version is the same schoolbook product one level up.
pub(crate) mod multiplication {
    use super::move_to_vectoreyes::*;
    use vectoreyes::U64x2;

    // Algorithm 1 from page 12 of https://is.gd/tOd246
    //
    // The paper describes this as, "one iteration carry-less schoolbook" multiplication. In
    // comparison to Algorithm 2 ("one iteration carry-less Karatsuba"), this performed about the
    // same on aarch64, but appreciably better on x86_64, in benchmarks.
    #[inline(always)]
    pub(crate) fn clmul(a: u128, b: u128) -> (u128, u128) {
        let a: U64x2 = bytemuck::cast(a); // [A1 : A0]
        let b: U64x2 = bytemuck::cast(b); // [B1 : B0]

        let c = carryless_mul_64bit::<false, false>(a, b); // [C1 : C0] = A0 • B0
        let d = carryless_mul_64bit::<true, true>(a, b); // [D1 : D0] = A1 • B1
        let e = carryless_mul_64bit::<true, false>(a, b); // [E1 : E0] = A0 • B1
        let f = carryless_mul_64bit::<false, true>(a, b); // [F1 : F0] = A1 • B0

        let e_f = e ^ f; // common term: [F1 ⊕ E1 : F0 ⊕ E0]
        let lo = c ^ shl!(e_f, 64); // lo bits of (5): [F0 ⊕ E0 ⊕ C1 : C0]
        let hi = d ^ srl!(e_f, 64); // hi bits of (5): [D1 : F1 ⊕ E1 ⊕ D0]

        // Equation (5): [D1 : F1 ⊕ E1 ⊕ D0 : F0 ⊕ E0 ⊕ C1 : C0]
        (bytemuck::cast(hi), bytemuck::cast(lo))
    }

    // Reduction mod x^128 + x^7 + x^2 + x + 1 using clmul folding.
    //
    // In comparison to `reduce`, below, this is about 3% faster an aarch64, but about 25% slower on
    // x86_64. The aarch64 speedup is probably not enough to want to complicate our implementation
    // with, but I'm keeping it here for now, in case we want to eke out a little extra speed.
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn reduce_clmul_fold(hi: u128, lo: u128) -> u128 {
        let modulus: U64x2 = bytemuck::cast(0x87_u128);
        let hi: U64x2 = bytemuck::cast(hi);
        let lo: U64x2 = bytemuck::cast(lo);

        let r0 = carryless_mul_64bit::<false, false>(hi, modulus);
        let r1 = carryless_mul_64bit::<false, true>(hi, modulus);

        let t = r0 ^ shl!(r1, 64);
        let over = srl!(r1, 64); // ≤ 7 bits
        let over_r = over ^ shl!(over, lt64 1) ^ shl!(over, lt64 2) ^ shl!(over, lt64 7);

        bytemuck::cast(lo ^ t ^ over_r)
    }

    // Algorithm (4) from page 15 of https://is.gd/tOd246
    // Reduce the polynomial represented in bits over x^128 + x^7 + x^2 + x + 1
    #[inline(always)]
    pub(crate) fn reduce(hi: u128, lo: u128) -> u128 {
        let hi: U64x2 = bytemuck::cast(hi);
        let lo: U64x2 = bytemuck::cast(lo);

        // [X3 : X2 : X1 : X0] = X
        let x3 = srl!(hi, 64);

        let a = srl!(x3, lt64 63); // A = X3 >> 63
        let b = srl!(x3, lt64 62); // B = X3 >> 62
        let c = srl!(x3, lt64 57); // C = X3 >> 57

        let x3_d = hi ^ a ^ b ^ c; // [X3 : D] = [X3 : X2 ⊕ A ⊕ B ⊕ C]
        let e = shl!(x3_d, lt64 1); // [E1 : E0] = [X3 : D] << 1
        let f = shl!(x3_d, lt64 2); // [F1 : F0] = [X3 : D] << 2
        let g = shl!(x3_d, lt64 7); // [G1 : G0] = [X3 : D] << 7

        // [H1 : H0] = [X3 ⊕ E1 ⊕ F1 ⊕ G1 : D ⊕ E0 ⊕ F0 ⊕ G0]
        let h = x3_d ^ e ^ f ^ g;
        bytemuck::cast(lo ^ h) // [X1 ⊕ H1 : X0 ⊕ H0]
    }

    #[cfg(test)]
    mod test {
        use super::{super::polynomial_modulus_f128b, *};
        use crate::{F2, F128b};
        use proptest::{prelude::*, prop_assert_eq, test_runner::TestCaseError};
        use swanky_field::FiniteField;
        use swanky_polynomial::Polynomial;
        use vectoreyes::U8x16;

        fn poly_from_128(x: u128) -> Polynomial<F2> {
            let x = F128b(x).decompose();
            Polynomial {
                constant: x[0],
                coefficients: x[1..].to_vec(),
            }
        }

        fn clmul_ref(a: u128, b: u128) -> (u128, u128) {
            let [lo, hi] = U8x16::from(a).carryless_mul_wide(U8x16::from(b));
            let lo: u128 = bytemuck::cast(lo);
            let hi: u128 = bytemuck::cast(hi);
            (hi, lo)
        }

        fn reduce_ref(hi: u128, lo: u128) -> Result<Polynomial<F2>, TestCaseError> {
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

            fn assert_div_mod(
                poly: &Polynomial<F2>,
                quotient: &Polynomial<F2>,
                remainder: &Polynomial<F2>,
            ) -> Result<(), TestCaseError> {
                let mut tmp = quotient.clone();
                tmp *= &polynomial_modulus_f128b();
                tmp += remainder;
                prop_assert_eq!(poly, &tmp);
                Ok(())
            }

            let poly = poly_from_upper_and_lower_128(hi, lo);
            let (poly_quotient, poly_reduced) = poly.divmod(&polynomial_modulus_f128b());
            assert_div_mod(&poly, &poly_quotient, &poly_reduced)?;

            Ok(poly_reduced)
        }

        proptest! {
            #[test]
            fn test_carryless_mul_128bit(a: u128, b: u128) {
                prop_assert_eq!(clmul(a, b), clmul_ref(a, b));
            }

            #[test]
            fn test_reduce(upper in any::<u128>(), lower in any::<u128>()) {
                let poly_reduced = reduce_ref(upper, lower)?;
                prop_assert_eq!(poly_from_128(reduce(upper, lower)), poly_reduced);
            }
        }
    }
}

impl<'a> MulAssign<&'a F128b> for F128b {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a F128b) {
        use multiplication::*;
        let (hi, lo) = clmul(self.0, rhs.0);
        self.0 = reduce(hi, lo);
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

impl From<U8x16> for F128b {
    fn from(value: U8x16) -> Self {
        Self(bytemuck::cast(value))
    }
}
impl From<F128b> for U8x16 {
    fn from(value: F128b) -> Self {
        U8x16::from(value.0)
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
    use crate::F2;

    use super::F128b;
    use proptest::prelude::*;
    use vectoreyes::U8x16;
    swanky_field_test::test_field!(test_field, F128b, crate::f128b::polynomial_modulus_f128b);
    proptest! {
        #[test]
        fn lsb_works(input in any::<u128>()) {
            prop_assert_eq!(F128b::from(U8x16::from(input)).lsb(), F2::from((input & 1) != 0));
        }
    }
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
