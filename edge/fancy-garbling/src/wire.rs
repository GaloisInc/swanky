//! Wirelabels for use in garbled circuits.
//!
//! This module contains a [`WireLabel`] trait, alongside various instantiations
//! of this trait. The [`WireLabel`] trait is the core underlying primitive used
//! in garbled circuits, and represents an encoding of the value on any given
//! wire of the circuit.

use crate::util;
use fancy_traits::HasModulus;
use rand::CryptoRng;
use swanky_cr_hash::TweakableCircularCorrelationRobustHash;
use vectoreyes::{
    U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

mod mod2;
pub use mod2::WireMod2;
mod mod3;
pub use mod3::WireMod3;
mod modq;
pub use modq::WireModQ;
mod npaths_tab;

/// Hash a batch of wires, using the same tweak for each wire.
pub fn hash_wires<const Q: usize, W: WireLabel>(wires: [&W; Q], tweak: u128) -> [U8x16; Q]
where
    ArrayUnrolledOps: UnrollableArraySize<Q>,
{
    let batch = wires.array_map(|x| x.to_repr());
    TweakableCircularCorrelationRobustHash::fixed_key().hash_many(batch, tweak)
}

/// A marker trait indicating that the given [`WireLabel`] instantiation
/// supports arithmetic operations.
pub trait ArithmeticWire: Clone {}

/// A trait that defines a wirelabel as used in garbled circuits.
///
/// At its core, a [`WireLabel`] is a way of encoding values, and operating on
/// those encoded values.
pub trait WireLabel:
    Clone
    + core::fmt::Debug
    + core::default::Default
    + HasModulus
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + core::ops::Sub<Output = Self>
    + core::ops::SubAssign
    + core::ops::Neg<Output = Self>
    + core::ops::Mul<u16, Output = Self>
    + core::ops::MulAssign<u16>
{
    /// Converts a [`WireLabel`] into its [`U8x16`] representation.
    fn to_repr(&self) -> U8x16;

    /// The color digit of the wire.
    fn color(&self) -> u16;

    /// Converts a [`U8x16`] into its [`WireLabel`] representation, based on the
    /// modulus `q`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn from_repr(inp: U8x16, q: u16) -> Self;

    /// A random [`WireLabel`] `mod q`, with the first digit set to `1`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn rand_delta<R: CryptoRng>(rng: &mut R, q: u16) -> Self;

    /// A random [`WireLabel`] `mod q`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn rand<R: CryptoRng>(rng: &mut R, q: u16) -> Self;

    /// Converts a hashed block into a valid wire of the given modulus `q`.
    ///
    /// This is useful when separately using [`hash_wires`] to hash a set of
    /// wires in one shot for efficiency reasons.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn hash_to_mod(hash: U8x16, q: u16) -> Self;

    /// Computes the hash of this [`WireLabel`], converting the result back into
    /// a [`WireLabel`] based on the modulus `q`.
    ///
    /// This is equivalent to `WireLabel::hash_to_mod(self.hash(tweak), q)`, and
    /// is useful when stringing together a sequence of operations on a
    /// [`WireLabel`].
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn hashback(&self, tweak: u128, q: u16) -> Self {
        let hash = self.hash(tweak);
        Self::hash_to_mod(hash, q)
    }

    /// Computes the hash of the [`WireLabel`].
    fn hash(&self, tweak: u128) -> U8x16 {
        TweakableCircularCorrelationRobustHash::fixed_key().hash(self.to_repr(), tweak)
    }

    /// Computes a [`WireLabel`] for `x % q`, returning both the zero
    /// [`WireLabel`] as well as the [`WireLabel`] for `x % q`.
    fn constant<RNG: CryptoRng>(x: u16, q: u16, delta: &Self, rng: &mut RNG) -> (Self, Self) {
        let zero = Self::rand(rng, q);
        let wire = zero.clone() + delta.clone() * x;
        (zero, wire)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A [`WireLabel`] that supports all possible moduli
pub enum AllWire {
    /// A `mod 2` [`WireLabel`].
    Mod2(WireMod2),
    /// A `mod 3` [`WireLabel`].
    Mod3(WireMod3),
    /// A `mod q` [`WireLabel`], where `3 < q < 2^16`.
    ModN(WireModQ),
}

impl HasModulus for AllWire {
    fn modulus(&self) -> u16 {
        match &self {
            AllWire::Mod2(x) => x.modulus(),
            AllWire::Mod3(x) => x.modulus(),
            AllWire::ModN(x) => x.modulus(),
        }
    }
}

impl core::default::Default for AllWire {
    fn default() -> Self {
        Self::Mod2(Default::default())
    }
}

impl core::ops::Add for AllWire {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (p, q) = (self.modulus(), rhs.modulus());
        match (self, rhs) {
            (Self::Mod2(x), Self::Mod2(y)) => Self::Mod2(x + y),
            (Self::Mod3(x), Self::Mod3(y)) => Self::Mod3(x + y),
            (Self::ModN(x), Self::ModN(y)) => Self::ModN(x + y),
            _ => panic!("unequal moduli: {p} != {q}"),
        }
    }
}

impl core::ops::AddAssign for AllWire {
    fn add_assign(&mut self, rhs: Self) {
        let (p, q) = (self.modulus(), rhs.modulus());
        match (self, rhs) {
            (Self::Mod2(x), Self::Mod2(y)) => *x += y,
            (Self::Mod3(x), Self::Mod3(y)) => *x += y,
            (Self::ModN(x), Self::ModN(y)) => *x += y,
            _ => panic!("unequal moduli: {p} != {q}"),
        }
    }
}

impl core::ops::Sub for AllWire {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for AllWire {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl core::ops::Neg for AllWire {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            Self::Mod2(x) => Self::Mod2(-x),
            Self::Mod3(x) => Self::Mod3(-x),
            Self::ModN(x) => Self::ModN(-x),
        }
    }
}

impl core::ops::Mul<u16> for AllWire {
    type Output = Self;

    fn mul(self, rhs: u16) -> Self::Output {
        match self {
            Self::Mod2(x) => Self::Mod2(x * rhs),
            Self::Mod3(x) => Self::Mod3(x * rhs),
            Self::ModN(x) => Self::ModN(x * rhs),
        }
    }
}

impl core::ops::MulAssign<u16> for AllWire {
    fn mul_assign(&mut self, rhs: u16) {
        match self {
            Self::Mod2(x) => {
                *x *= rhs;
            }
            Self::Mod3(x) => {
                *x *= rhs;
            }
            Self::ModN(x) => {
                *x *= rhs;
            }
        };
    }
}

impl WireLabel for AllWire {
    fn rand_delta<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand_delta(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand_delta(rng, q)),
            _ => AllWire::ModN(WireModQ::rand_delta(rng, q)),
        }
    }

    fn to_repr(&self) -> U8x16 {
        match &self {
            AllWire::Mod2(x) => x.to_repr(),
            AllWire::Mod3(x) => x.to_repr(),
            AllWire::ModN(x) => x.to_repr(),
        }
    }
    fn color(&self) -> u16 {
        match &self {
            AllWire::Mod2(x) => x.color(),
            AllWire::Mod3(x) => x.color(),
            AllWire::ModN(x) => x.color(),
        }
    }
    fn from_repr(inp: U8x16, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::from_repr(inp, q)),
            3 => AllWire::Mod3(WireMod3::from_repr(inp, q)),
            _ => AllWire::ModN(WireModQ::from_repr(inp, q)),
        }
    }

    fn rand<R: CryptoRng>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand(rng, q)),
            _ => AllWire::ModN(WireModQ::rand(rng, q)),
        }
    }

    fn hash_to_mod(hash: U8x16, q: u16) -> Self {
        if q == 3 {
            AllWire::Mod3(WireMod3::encode_block_mod3(hash))
        } else {
            Self::from_repr(hash, q)
        }
    }
}
fn _unrank(inp: u128, q: u16) -> Vec<u16> {
    let mut x = inp;
    let ndigits = util::digits_per_u128(q);
    let npaths_tab = npaths_tab::lookup(q);
    x %= npaths_tab[ndigits - 1] * q as u128;

    let mut ds = vec![0; ndigits];
    for i in (0..ndigits).rev() {
        let npaths = npaths_tab[i];

        if q <= 23 {
            // linear search
            let mut acc = 0;
            for j in 0..q {
                acc += npaths;
                if acc > x {
                    x -= acc - npaths;
                    ds[i] = j;
                    break;
                }
            }
        } else {
            // naive division
            let d = x / npaths;
            ds[i] = d as u16;
            x -= d * npaths;
        }
        // } else {
        //     // binary search
        //     let mut low = 0;
        //     let mut high = q;
        //     loop {
        //         let cur = (low + high) / 2;
        //         let l = npaths * cur as u128;
        //         let r = npaths * (cur as u128 + 1);
        //         if x >= l && x < r {
        //             x -= l;
        //             ds[i] = cur;
        //             break;
        //         }
        //         if x < l {
        //             high = cur;
        //         } else {
        //             // x >= r
        //             low = cur;
        //         }
        //     }
        // }
    }
    ds
}

impl ArithmeticWire for AllWire {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::as_base_q_u128;
    use fancy_circuits::util::RngExt;
    use itertools::Itertools;
    use rand::{RngExt as _, rng};

    #[test]
    fn packing() {
        let rng = &mut rng();
        for q in 2..256 {
            for _ in 0..1000 {
                let w = AllWire::rand(rng, q);
                assert_eq!(w, AllWire::from_repr(w.to_repr(), q));
            }
        }
    }

    #[test]
    fn base_conversion_lookup_method() {
        let rng = &mut rng();
        for _ in 0..1000 {
            let q = 5 + (rng.random::<u16>() % 110);
            let x = rng.random::<u128>();
            let w = WireModQ::from_repr(U8x16::from(x), q);
            let should_be = as_base_q_u128(x, q);
            assert_eq!(w.ds, should_be, "x={} q={}", x, q);
        }
    }

    #[test]
    fn hash() {
        let mut rng = rng();
        for _ in 0..100 {
            let q = 2 + (rng.random::<u16>() % 110);
            let x = AllWire::rand(&mut rng, q);
            let y = x.hashback(1u128, q);
            assert!(x != y);
            match y {
                AllWire::Mod2(WireMod2 { val }) => assert!(u128::from(val) > 0),
                AllWire::Mod3(WireMod3 { lsb, msb }) => assert!(lsb > 0 && msb > 0),
                AllWire::ModN(WireModQ { ds, .. }) => assert!(!ds.iter().all(|&y| y == 0)),
            }
        }
    }

    #[test]
    fn negation() {
        let rng = &mut rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(rng, q);
            let xneg = -x.clone();
            if q != 2 {
                assert!(x != xneg);
            }
            let y = -xneg;
            assert_eq!(x, y);
        }
    }

    #[test]
    #[allow(clippy::erasing_op)]
    fn arithmetic() {
        let mut rng = rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            let y = AllWire::rand(&mut rng, q);
            assert_eq!(x.clone() * 0, x.clone() - x.clone());
            assert_eq!(x.clone() * q, x.clone() - x.clone());
            assert_eq!(x.clone() + x.clone(), x.clone() * 2);
            assert_eq!(x.clone() + x.clone() + x.clone(), x.clone() * 3);
            assert_eq!(-(-x.clone()), x);
            if q == 2 {
                assert_eq!(x.clone() + y.clone(), x.clone() - y.clone());
            } else {
                assert_eq!(x.clone() + -x.clone(), x.clone() - x.clone());
                assert_eq!(x.clone() + -y.clone(), x.clone() - y.clone());
            }
            let mut w = x.clone();
            let z = w.clone() + y.clone();
            w += y;
            assert_eq!(w, z);

            w = x.clone();
            w *= 2;
            assert_eq!(x.clone() + x.clone(), w);

            w = x.clone();
            w = -w;
            assert_eq!(-x, w);
        }
    }

    #[test]
    fn ndigits_correct() {
        let mut rng = rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = WireModQ::rand(&mut rng, q);
            assert_eq!(x.ds.len(), util::digits_per_u128(q));
        }
    }

    #[test]
    fn parallel_hash() {
        let n = 1000;
        let mut rng = rng();
        let q = rng.gen_modulus();
        let ws = (0..n).map(|_| AllWire::rand(&mut rng, q)).collect_vec();

        let mut handles = Vec::new();
        for w in ws.iter() {
            let w_ = w.clone();
            let h = std::thread::spawn(move || w_.hash(0u128));
            handles.push(h);
        }
        let hashes = handles.into_iter().map(|h| h.join().unwrap()).collect_vec();

        let should_be = ws.iter().map(|w| w.hash(0u128)).collect_vec();

        assert_eq!(hashes, should_be);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_allwire() {
        let mut rng = rng();
        for q in 2..16 {
            let w = AllWire::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: AllWire = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }
}
