use crate::{ArithmeticWireLabel, WireLabel, wire::_unrank};
use fancy_traits::HasModulus;
use rand::{CryptoRng, RngExt};
use vectoreyes::U8x16;

/// Intermediate struct to deserialize WireMod3 to
///
/// Checks that both lsb and msb are not set before allowing to convert to WireMod3
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct UntrustedWireMod3 {
    /// The least-significant bits of each `mod-3` element.
    lsb: u64,
    /// The most-significant bits of each `mod-3` element.
    msb: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<UntrustedWireMod3> for WireMod3 {
    type Error = swanky_error::Error;

    fn try_from(wire: UntrustedWireMod3) -> Result<Self, Self::Error> {
        swanky_error::ensure!(
            wire.lsb & wire.msb == 0,
            swanky_error::ErrorKind::OtherError,
            "Mod 3 wire is ill-formed",
        );
        Ok(WireMod3 {
            lsb: wire.lsb,
            msb: wire.msb,
        })
    }
}

/// Representation of a `mod-3` wire.
///
/// We represent a `mod-3` wire by 64 `mod-3` elements. These elements are
/// stored as follows: the least-significant bits of each element are stored
/// in `lsb` and the most-significant bits of each element are stored in
/// `msb`. This representation allows for efficient addition and
/// multiplication as described here by the paper "Hardware Implementation
/// of Finite Fields of Characteristic Three." D. Page, N.P. Smart. CHES
/// 2002. Link:
/// <https://link.springer.com/content/pdf/10.1007/3-540-36400-5_38.pdf>.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "UntrustedWireMod3"))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod3 {
    /// The least-significant bits of each `mod-3` element.
    pub(crate) lsb: u64,
    /// The most-significant bits of each `mod-3` element.
    pub(crate) msb: u64,
}

impl HasModulus for WireMod3 {
    fn modulus(&self) -> u16 {
        3
    }
}

impl core::ops::Add for WireMod3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a1 = self.lsb;
        let a2 = self.msb;
        let b1 = rhs.lsb;
        let b2 = rhs.msb;

        let t = (a1 | b2) ^ (a2 | b1);
        let c1 = (a2 | b2) ^ t;
        let c2 = (a1 | b1) ^ t;
        Self { lsb: c1, msb: c2 }
    }
}

impl core::ops::AddAssign for WireMod3 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl core::ops::Sub for WireMod3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for WireMod3 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl core::ops::Neg for WireMod3 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // Negation just involves swapping `lsb` and `msb`.
        let mut output = self;
        std::mem::swap(&mut output.lsb, &mut output.msb);
        output
    }
}

impl core::ops::Mul<u16> for WireMod3 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: u16) -> Self::Output {
        let c = rhs % 3;
        match c {
            0 => Self { msb: 0, lsb: 0 },
            1 => self,
            2 => Self {
                msb: self.lsb,
                lsb: self.msb,
            },
            _ => unreachable!("Due to initial `rhs % 3`"),
        }
    }
}

impl core::ops::MulAssign<u16> for WireMod3 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, rhs: u16) {
        let c = rhs % 3;
        match c {
            0 => {
                self.msb = 0;
                self.lsb = 0;
            }
            1 => {}
            2 => {
                std::mem::swap(&mut self.lsb, &mut self.msb);
            }
            _ => unreachable!("Due to initial `rhs % 3`"),
        }
    }
}

impl WireMod3 {
    /// We have to convert `block` into a valid `Mod3` encoding.
    ///
    /// We do this by computing the `Mod3` digits using `_unrank`,
    /// and then map these to a `Mod3` encoding.
    pub(crate) fn encode_block_mod3(block: U8x16) -> Self {
        let mut lsb = 0u64;
        let mut msb = 0u64;
        let mut ds = _unrank(u128::from(block), 3);
        for (i, v) in ds.drain(..64).enumerate() {
            lsb |= ((v & 1) as u64) << i;
            msb |= (((v >> 1) & 1u16) as u64) << i;
        }
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }
}

impl WireLabel for WireMod3 {
    fn rand_delta<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand_delta] Expected modulo 3. Got {}", q);
        }
        let mut w = Self::rand(rng, 3);
        w.lsb |= 1;
        w.msb &= 0xFFFF_FFFF_FFFF_FFFE;
        w
    }

    fn to_repr(&self) -> U8x16 {
        // This function converts a [`WireMod3`] into its [`Block`] representation.
        // The two 64b values stored in [`WireMod3`], i.e. the lsb and msb, and packed
        // into a 128b value as a [`Block`].
        (((self.msb as u128) << 64) | (self.lsb as u128)).into()
    }

    fn color(&self) -> u16 {
        let color = (((self.msb & 1) as u16) << 1) | ((self.lsb & 1) as u16);
        debug_assert_ne!(color, 3);
        color
    }

    fn from_repr(inp: U8x16, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::from_block] Expected mod 3. Got mod {}", q)
        }
        // This function converts a Block into its WireLabel representation
        // by splitting the Block into two u64, its least significant bits and
        // its most significant bits.
        let inp = u128::from(inp);
        let lsb = inp as u64;
        let msb = (inp >> 64) as u64;
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn rand<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand] Expected mod 3. Got mod {}", q)
        }
        let mut lsb = 0u64;
        let mut msb = 0u64;
        for (i, v) in (0..64).map(|_| rng.random::<u8>() % 3).enumerate() {
            lsb |= ((v & 1) as u64) << i;
            msb |= (((v >> 1) & 1) as u64) << i;
        }
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn hash_to_mod(hash: U8x16, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::hash_to_mod] Expected mod 3. Got mod {}", q)
        }
        Self::encode_block_mod3(hash)
    }
}

impl ArithmeticWireLabel for WireMod3 {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_mod3() {
        use crate::{WireLabel, WireMod3};
        use rand::rng;

        let mut rng = rng();
        let w = WireMod3::rand(&mut rng, 3);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod3 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_mod3() {
        use crate::{WireLabel, WireMod3};
        use rand::rng;

        let mut rng = rng();
        let mut w = WireMod3::rand(&mut rng, 3);

        // lsb and msb can't both be set
        w.lsb |= 1;
        w.msb |= 1;
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: Result<WireMod3, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
}
