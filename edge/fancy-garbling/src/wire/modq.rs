use crate::{ArithmeticWireLabel, WireLabel, util, wire::_unrank};
use fancy_traits::HasModulus;
use rand::{CryptoRng, RngExt};
use vectoreyes::U8x16;

/// Intermediate struct to deserialize WireModQ to
///
/// Checks that modulus is at least 2
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct UntrustedWireModQ {
    /// The modulus of the wire label
    q: u16, // Assuming mod can fit in u16
    /// A list of `mod-q` digits.
    ds: Vec<u16>,
}

#[cfg(feature = "serde")]
impl TryFrom<UntrustedWireModQ> for WireModQ {
    type Error = swanky_error::Error;

    fn try_from(wire: UntrustedWireModQ) -> Result<Self, Self::Error> {
        swanky_error::ensure!(
            wire.q >= 2,
            swanky_error::ErrorKind::OtherError,
            "Modulus must be at least two",
        );

        // Check correct length and make sure all values are less than the modulus
        let expected_len = crate::util::digits_per_u128(wire.q);
        let given_len = wire.ds.len();
        swanky_error::ensure!(
            given_len == expected_len,
            swanky_error::ErrorKind::OtherError,
            "Invalid number of digits. Expected: {expected_len}. Got: {given_len}"
        );
        if let Some(i) = wire.ds.iter().position(|&x| x >= wire.q) {
            swanky_error::bail!(
                swanky_error::ErrorKind::OtherError,
                "Digit {i} is greater than the modulus",
            );
        }
        Ok(WireModQ {
            q: wire.q,
            ds: wire.ds,
        })
    }
}

// Assuming mod can fit in u16
/// Representation of a `mod-q` wire.
///
/// We represent a `mod-q` wire for `q > 3` by the modulus`q` alongside a
/// list of `mod-q` digits.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "UntrustedWireModQ"))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WireModQ {
    /// The modulus of the wire label
    q: u16,
    /// A list of `mod-q` digits.
    pub(crate) ds: Vec<u16>,
}

impl HasModulus for WireModQ {
    fn modulus(&self) -> u16 {
        self.q
    }
}

impl core::ops::Add for WireModQ {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(self.q, rhs.q);

        let mut xs = self.ds.clone();
        let ys = &rhs.ds;
        let q = self.q;

        debug_assert_eq!(xs.len(), ys.len());
        xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });
        Self { ds: xs, q }
    }
}

impl core::ops::AddAssign for WireModQ {
    fn add_assign(&mut self, rhs: Self) {
        assert_eq!(self.q, rhs.q);

        let q = self.q;

        debug_assert_eq!(self.ds.len(), rhs.ds.len());
        self.ds.iter_mut().zip(rhs.ds.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });
    }
}

impl core::ops::Sub for WireModQ {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for WireModQ {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl core::ops::Neg for WireModQ {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let q = self.q;
        let mut ds = self.ds.clone();
        ds.iter_mut().for_each(|d| {
            if *d > 0 {
                *d = q - *d;
            } else {
                *d = 0;
            }
        });
        Self { q, ds }
    }
}

impl core::ops::Mul<u16> for WireModQ {
    type Output = Self;

    fn mul(self, rhs: u16) -> Self::Output {
        let q = self.q;
        let mut ds = self.ds.clone();
        ds.iter_mut()
            .for_each(|d| *d = (*d as u32 * rhs as u32 % q as u32) as u16);
        Self { ds, q }
    }
}

impl core::ops::MulAssign<u16> for WireModQ {
    fn mul_assign(&mut self, rhs: u16) {
        let q = self.q;
        self.ds
            .iter_mut()
            .for_each(|d| *d = (*d as u32 * rhs as u32 % q as u32) as u16);
    }
}

impl WireLabel for WireModQ {
    fn rand_delta<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::rand_delta] Modulus must be at least 2. Got {}",
                q
            );
        }
        let mut w = Self::rand(rng, q);
        w.ds[0] = 1;
        w
    }

    fn to_repr(&self) -> U8x16 {
        // This function converts a [`WireMod3`] into its [`Block`] representation.
        // The values stored in [`WireModQ`] are repacked depending on q
        // into a 128b value as a [`Block`].
        util::from_base_q(&self.ds, self.q).into()
    }

    fn color(&self) -> u16 {
        let color = self.ds[0];
        debug_assert!(color < self.q);
        color
    }

    fn from_repr(inp: U8x16, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::from_block] Modulus must be at least 2. Got {}",
                q
            );
        }
        // This function converts a Block into its WireLabel representation
        // by splitting the Block into several digits mod q that can each fit
        // into 128b.
        let ds = if q.is_power_of_two() {
            // It's a power of 2, just split the digits.
            let ndigits = util::digits_per_u128(q);
            let width = 128 / ndigits;
            let mask = (1 << width) - 1;
            let x = u128::from(inp);
            (0..ndigits)
                .map(|i| ((x >> (width * i)) & mask) as u16)
                .collect::<Vec<u16>>()
        } else if q <= 23 {
            _unrank(u128::from(inp), q)
        } else {
            // If all else fails, do unrank using naive division.
            _unrank(u128::from(inp), q)
        };
        Self { q, ds }
    }

    fn rand<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        if q < 2 {
            panic!("[WireModQ::rand] Modulus must be at least 2. Got {}", q);
        }
        let ds = (0..util::digits_per_u128(q))
            .map(|_| rng.random::<u16>() % q)
            .collect();
        Self { q, ds }
    }

    fn hash_to_mod(hash: U8x16, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::hash_to_mod] Modulus must be at least 2. Got {}",
                q
            );
        }
        Self::from_repr(hash, q)
    }
}

impl ArithmeticWireLabel for WireModQ {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use super::WireModQ;
    #[cfg(feature = "serde")]
    use crate::WireLabel;
    #[cfg(feature = "serde")]
    use rand::RngExt;
    #[cfg(feature = "serde")]
    use rand::rng;

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_modQ() {
        let mut rng = rng();

        for _ in 0..16 {
            let mut q: u16 = rng.random();
            while q < 2 {
                q = rng.random();
            }
            let w = WireModQ::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: WireModQ = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_mod() {
        let mut rng = rng();
        let mut q: u16 = rng.random();
        while q < 2 {
            q = rng.random();
        }

        let mut w = WireModQ::rand(&mut rng, q);

        // Manually mess with the modulus
        w.q = 1;
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_ds_mod() {
        let serialized: String = "{\"q\":2,\"ds\":[1,1,0,1,0,5,1,0,0,0,1,1,1,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,0,0]}".to_string();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_ds_count() {
        let serialized: String = "{\"q\":2,\"ds\":[1,1,0,1,0,1,0,0,0,1,1,1,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,0,0]}".to_string();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
}
