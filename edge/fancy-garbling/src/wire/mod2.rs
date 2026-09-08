use crate::{BinaryWireLabel, WireLabel, hash_wires, util::tweak2};
use fancy_traits::HasModulus;
use rand::{CryptoRng, RngExt};
use subtle::ConditionallySelectable;
use vectoreyes::{SimdBase, U8x16};

impl HasModulus for WireMod2 {
    fn modulus(&self) -> u16 {
        2
    }
}

/// Representation of a `mod-2` wire.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod2 {
    /// A 128-bit value.
    pub(crate) val: U8x16,
}

impl core::ops::Add for WireMod2 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val ^ rhs.val,
        }
    }
}

impl core::ops::AddAssign for WireMod2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.val ^= rhs.val;
    }
}

impl core::ops::Sub for WireMod2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for WireMod2 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl core::ops::Neg for WireMod2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // Do nothing. Additive inverse is a no-op for mod 2.
        self
    }
}

impl core::ops::Mul<u16> for WireMod2 {
    type Output = Self;

    fn mul(self, rhs: u16) -> Self::Output {
        if rhs & 1 == 0 {
            Self {
                val: Default::default(),
            }
        } else {
            self
        }
    }
}

impl core::ops::MulAssign<u16> for WireMod2 {
    fn mul_assign(&mut self, rhs: u16) {
        if rhs & 1 == 0 {
            self.val = Default::default();
        }
    }
}

impl ConditionallySelectable for WireMod2 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        WireMod2::from_repr(
            U8x16::conditional_select(&a.to_repr(), &b.to_repr(), choice),
            2,
        )
    }
}

impl WireLabel for WireMod2 {
    fn rand_delta<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand_delta] Expected modulo 2. Got {}", q);
        }
        let mut w = Self::rand(rng, q);
        w.val |= U8x16::set_lo(1);
        w
    }

    fn to_repr(&self) -> U8x16 {
        // This function converts a [`WireMod2`] into its [`U8x16`] representation.
        // Since the value of a [`WireMod2`] is a 128b value, its directly returned
        // as a [`U8x16`].
        self.val
    }

    fn color(&self) -> u16 {
        // This extracts the least-significant bit of the U8x16.
        (self.val.extract::<0>() & 1) as u16
    }

    fn from_repr(inp: U8x16, q: u16) -> Self {
        // This function converts a Block into its WireLabel representation
        // by just setting the value of WireMod2 to the Block (i.e. the
        // wire's 128b value).
        if q != 2 {
            panic!("[WireMod2::from_block] Expected modulo 2. Got {}", q);
        }
        Self { val: inp }
    }

    fn rand<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand] Expected modulo 2. Got {}", q);
        }

        Self { val: rng.random() }
    }

    fn hash_to_mod(hash: U8x16, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::hash_to_mod] Expected modulo 2. Got {}", q);
        }
        Self::from_repr(hash, q)
    }
}

impl BinaryWireLabel for WireMod2 {
    fn garble_and_gate(gate_num: usize, A: &Self, B: &Self, delta: &Self) -> (U8x16, U8x16, Self) {
        let q = A.modulus();
        let D = delta;

        let r = B.color(); // secret value known only to the garbler (ev knows r+b)

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = A.color(); // alpha = -A.color
        let X1 = *A + *D * alpha;

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (q - B.color()) % q;
        let Y1 = *B + *D * beta;

        let AD = *A + *D;
        let BD = *B + *D;

        // idx is always boolean for binary gates, so it can be represented as a `u8`
        let a_selector = (A.color() as u8).into();
        let b_selector = (B.color() as u8).into();

        let B = Self::conditional_select(&BD, B, b_selector);
        let newA = Self::conditional_select(&AD, A, a_selector);
        let idx = u8::conditional_select(&(r as u8), &0u8, a_selector);

        let [hashA, hashB, hashX, hashY] = hash_wires([&newA, &B, &X1, &Y1], g);

        let X = Self::hash_to_mod(hashX, q) + *D * (alpha * r % q);
        let Y = Self::hash_to_mod(hashY, q);

        let gate0 =
            hashA ^ U8x16::conditional_select(&X.to_repr(), &(X + *D).to_repr(), idx.into());
        let gate1 = hashB ^ (Y + *A).to_repr();

        (gate0, gate1, X + Y)
    }

    fn evaluate_and_gate(
        gate_num: usize,
        A: &Self,
        B: &Self,
        gate0: &U8x16,
        gate1: &U8x16,
    ) -> Self {
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = Self::from_repr(
            U8x16::conditional_select(&hashA, &(hashA ^ *gate0), (A.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let R = Self::from_repr(
            U8x16::conditional_select(&hashB, &(hashB ^ *gate1), (B.color() as u8).into()),
            2,
        );

        L + R + *A * B.color()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_mod2() {
        use crate::{WireLabel, WireMod2};
        use rand::rng;

        let mut rng = rng();
        let w = WireMod2::rand(&mut rng, 2);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod2 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }
}
