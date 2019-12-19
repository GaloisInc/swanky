// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Low-level operations on wire-labels, the basic building block of garbled circuits.

use crate::{fancy::HasModulus, util};
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{Block, AES_HASH};

mod npaths_tab;

/// The core wire-label type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub enum Wire {
    /// Representation of a `mod-2` wire.
    Mod2 {
        /// A 128-bit value.
        val: Block,
    },
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
    Mod3 {
        /// The least-significant bits of each `mod-3` element.
        lsb: u64,
        /// The most-significant bits of each `mod-3` element.
        msb: u64,
    },
    /// Representation of a `mod-q` wire.
    ///
    /// We represent a `mod-q` wire for `q > 3` by the modulus `q` alongside a
    /// list of `mod-q` digits.
    ModN {
        /// The modulus of this wire-label.
        q: u16,
        /// A list of `mod-q` digits.
        ds: Vec<u16>,
    },
}

impl std::default::Default for Wire {
    fn default() -> Self {
        Wire::Mod2 {
            val: Block::default(),
        }
    }
}

impl HasModulus for Wire {
    fn modulus(&self) -> u16 {
        match self {
            Wire::Mod2 { .. } => 2,
            Wire::Mod3 { .. } => 3,
            Wire::ModN { q, .. } => *q,
        }
    }
}

impl Wire {
    /// Get the digits of the wire.
    pub fn digits(&self) -> Vec<u16> {
        match self {
            Wire::Mod2 { val } => (0..128)
                .map(|i| ((u128::from(*val) >> i) as u16) & 1)
                .collect(),
            Wire::Mod3 { lsb, msb } => (0..64)
                .map(|i| (((lsb >> i) as u16) & 1) & ((((msb >> i) as u16) & 1) << 1))
                .collect(),
            Wire::ModN { ds, .. } => ds.clone(),
        }
    }

    fn _from_block_lookup(inp: Block, q: u16) -> Vec<u16> {
        debug_assert!(q < 256);
        debug_assert!(base_conversion::lookup_defined_for_mod(q));
        let bytes: [u8; 16] = inp.into();
        // The digits in position 15 will be the longest, so we can use stateful
        // (fast) base `q` addition.
        let mut ds = base_conversion::lookup_digits_mod_at_position(bytes[15], q, 15).to_vec();
        for i in 0..15 {
            let cs = base_conversion::lookup_digits_mod_at_position(bytes[i], q, i);
            util::base_q_add_eq(&mut ds, &cs, q);
        }
        // Drop the digits we won't be able to pack back in again, especially if
        // they get multiplied.
        ds.truncate(util::digits_per_u128(q));
        ds
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

    /// Unpack the wire represented by a `Block` with modulus `q`. Assumes that
    /// the block was constructed through the `Wire` API.
    pub fn from_block(inp: Block, q: u16) -> Self {
        if q == 2 {
            Wire::Mod2 { val: inp }
        } else if q == 3 {
            let inp = u128::from(inp);
            let lsb = inp as u64;
            let msb = (inp >> 64) as u64;
            debug_assert_eq!(lsb & msb, 0);
            Wire::Mod3 { lsb, msb }
        } else {
            let ds = if util::is_power_of_2(q) {
                // It's a power of 2, just split the digits.
                let ndigits = util::digits_per_u128(q);
                let width = 128 / ndigits;
                let mask = (1 << width) - 1;
                let x = u128::from(inp);
                (0..ndigits)
                    .map(|i| ((x >> (width * i)) & mask) as u16)
                    .collect::<Vec<u16>>()
            } else if q <= 23 {
                Self::_unrank(u128::from(inp), q)
            } else if base_conversion::lookup_defined_for_mod(q) {
                Self::_from_block_lookup(inp, q)
            } else {
                // If all else fails, do unrank using naive division.
                Self::_unrank(u128::from(inp), q)
            };
            Wire::ModN { q, ds }
        }
    }

    /// Pack the wire into a `Block`.
    pub fn as_block(&self) -> Block {
        match self {
            Wire::Mod2 { val } => *val,
            Wire::Mod3 { lsb, msb } => Block::from(((*msb as u128) << 64) | (*lsb as u128)),
            Wire::ModN { q, ref ds } => Block::from(util::from_base_q(ds, *q)),
        }
    }

    /// The zero wire with modulus `q`.
    pub fn zero(q: u16) -> Self {
        match q {
            0 => panic!("[Wire::zero] mod 0 not allowed!"),
            1 => panic!("[Wire::zero] mod 1 not allowed!"),
            2 => Wire::Mod2 {
                val: Default::default(),
            },
            3 => Wire::Mod3 {
                lsb: Default::default(),
                msb: Default::default(),
            },
            _ => Wire::ModN {
                q,
                ds: vec![0; util::digits_per_u128(q)],
            },
        }
    }

    /// Get a random wire label mod `q`, with the first digit set to `1`.
    pub fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
        let mut w = Self::rand(rng, q);
        match w {
            Wire::Mod2 { ref mut val } => *val = val.set_lsb(),
            Wire::Mod3 {
                ref mut lsb,
                ref mut msb,
            } => {
                // We want the color digit to be `1`, which requires setting the
                // appropriate `lsb` element to `1` and the appropriate `msb`
                // element to `0`.
                *lsb |= 1;
                *msb &= 0xFFFF_FFFF_FFFF_FFFE;
            }
            Wire::ModN { ref mut ds, .. } => ds[0] = 1,
        }
        w
    }

    /// Get the color digit of the wire.
    pub fn color(&self) -> u16 {
        match self {
            Wire::Mod2 { val } => val.lsb() as u16,
            Wire::Mod3 { lsb, msb } => {
                let color = (((msb & 1) as u16) << 1) | ((lsb & 1) as u16);
                debug_assert_ne!(color, 3);
                color
            }
            Wire::ModN { q, ref ds } => {
                let color = ds[0];
                debug_assert!(color < *q);
                color
            }
        }
    }

    /// Add two wires digit-wise, returning a new wire.
    pub fn plus(&self, other: &Self) -> Self {
        self.clone().plus_mov(other)
    }

    /// Add another wire digit-wise into this one. Assumes that both wires have
    /// the same modulus.
    pub fn plus_eq<'a>(&'a mut self, other: &Wire) -> &'a mut Wire {
        match (&mut *self, other) {
            (Wire::Mod2 { val: ref mut x }, Wire::Mod2 { val: ref y }) => {
                *x ^= *y;
            }
            (
                Wire::Mod3 {
                    lsb: ref mut a1,
                    msb: ref mut a2,
                },
                Wire::Mod3 { lsb: b1, msb: b2 },
            ) => {
                // As explained in the cited paper above, the following
                // operations do element-wise addition.
                let t = (*a1 | b2) ^ (*a2 | b1);
                let c1 = (*a2 | b2) ^ t;
                let c2 = (*a1 | b1) ^ t;
                *a1 = c1;
                *a2 = c2;
            }
            (
                Wire::ModN {
                    q: ref xmod,
                    ds: ref mut xs,
                },
                Wire::ModN {
                    q: ref ymod,
                    ds: ref ys,
                },
            ) => {
                debug_assert_eq!(xmod, ymod);
                debug_assert_eq!(xs.len(), ys.len());
                xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
                    let (zp, overflow) = (*x + y).overflowing_sub(*xmod);
                    *x = if overflow { *x + y } else { zp }
                });
            }
            _ => panic!("[Wire::plus_eq] unequal moduli!"),
        }

        self
    }

    /// Add another wire into this one, consuming it for chained computations.
    pub fn plus_mov(mut self, other: &Wire) -> Wire {
        self.plus_eq(other);
        self
    }

    /// Multiply each digit by a constant `c mod q`, returning a new wire.
    pub fn cmul(&self, c: u16) -> Self {
        self.clone().cmul_mov(c)
    }

    /// Multiply each digit by a constant `c mod q`.
    pub fn cmul_eq(&mut self, c: u16) -> &mut Wire {
        match self {
            Wire::Mod2 { val } => {
                if c & 1 == 0 {
                    *val = Block::default();
                }
            }
            Wire::Mod3 { lsb, msb } => match c {
                0 => {
                    *lsb = 0;
                    *msb = 0;
                }
                1 => {}
                2 => {
                    // Multiplication by two is the same as negation in `mod-3`,
                    // which just involves swapping `lsb` and `msb`.
                    std::mem::swap(lsb, msb);
                }
                c => {
                    self.cmul_eq(c % 3);
                }
            },
            Wire::ModN { q, ds } => {
                ds.iter_mut()
                    .for_each(|d| *d = (*d as u32 * c as u32 % *q as u32) as u16);
            }
        }
        self
    }

    /// Multiply each digit by a constant `c mod q`, consuming it for chained computations.
    pub fn cmul_mov(mut self, c: u16) -> Wire {
        self.cmul_eq(c);
        self
    }

    /// Negate all the digits `mod q`, returning a new wire.
    pub fn negate(&self) -> Self {
        self.clone().negate_mov()
    }

    /// Negate all the digits mod q.
    pub fn negate_eq(&mut self) -> &mut Wire {
        match self {
            Wire::Mod2 { .. } => {
                // Do nothing. Additive inverse is a no-op for mod 2.
            }
            Wire::Mod3 { lsb, msb } => {
                // Negation just involves swapping `lsb` and `msb`.
                std::mem::swap(lsb, msb);
            }
            Wire::ModN { q, ds } => {
                ds.iter_mut().for_each(|d| {
                    if *d > 0 {
                        *d = *q - *d;
                    } else {
                        *d = 0;
                    }
                });
            }
        }
        self
    }

    /// Negate all the digits `mod q`, consuming it for chained computations.
    pub fn negate_mov(mut self) -> Wire {
        self.negate_eq();
        self
    }

    /// Subtract two wires, returning the result.
    pub fn minus(&self, other: &Wire) -> Wire {
        self.clone().minus_mov(other)
    }

    /// Subtract a wire from this one.
    pub fn minus_eq<'a>(&'a mut self, other: &Wire) -> &'a mut Wire {
        self.plus_eq(&other.negate())
    }

    /// Subtract a wire from this one, consuming it for chained computations.
    pub fn minus_mov(mut self, other: &Wire) -> Wire {
        self.minus_eq(other);
        self
    }

    /// Get a random wire `mod q`.
    pub fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Wire {
        if q == 2 {
            Wire::Mod2 { val: rng.gen() }
        } else if q == 3 {
            // Generate 64 mod-three values and then embed them into `lsb` and
            // `msb`.
            let mut lsb = 0u64;
            let mut msb = 0u64;
            for (i, v) in (0..64).map(|_| rng.gen::<u8>() % 3).enumerate() {
                lsb |= ((v & 1) as u64) << i;
                msb |= (((v >> 1) & 1) as u64) << i;
            }
            debug_assert_eq!(lsb & msb, 0);
            Wire::Mod3 { lsb, msb }
        } else {
            let ds = (0..util::digits_per_u128(q))
                .map(|_| rng.gen::<u16>() % q)
                .collect();
            Wire::ModN { q, ds }
        }
    }

    /// Compute the hash of this wire.
    ///
    /// Uses fixed-key AES.
    #[inline(never)]
    pub fn hash(&self, tweak: Block) -> Block {
        AES_HASH.tccr_hash(tweak, self.as_block())
    }

    /// Compute the hash of this wire, converting the result back to a wire.
    ///
    /// Uses fixed-key AES.
    pub fn hashback(&self, tweak: Block, q: u16) -> Wire {
        let block = self.hash(tweak);
        if q == 3 {
            // We have to convert `block` into a valid `Mod3` encoding. We do
            // this by computing the `Mod3` digits using `_unrank`, and then map
            // these to a `Mod3` encoding.
            let mut lsb = 0u64;
            let mut msb = 0u64;
            let mut ds = Self::_unrank(u128::from(block), q);
            for (i, v) in ds.drain(..64).enumerate() {
                lsb |= ((v & 1) as u64) << i;
                msb |= (((v >> 1) & 1u16) as u64) << i;
            }
            debug_assert_eq!(lsb & msb, 0);
            Wire::Mod3 { lsb, msb }
        } else {
            Self::from_block(block, q)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    #[test]
    fn packing() {
        let ref mut rng = thread_rng();
        for q in 2..256 {
            for _ in 0..1000 {
                let w = Wire::rand(rng, q);
                assert_eq!(w, Wire::from_block(w.as_block(), q));
            }
        }
    }

    #[test]
    fn base_conversion_lookup_method() {
        let ref mut rng = thread_rng();
        for _ in 0..1000 {
            let q = 5 + (rng.gen_u16() % 110);
            let x = rng.gen_u128();
            let w = Wire::from_block(Block::from(x), q);
            let should_be = util::as_base_q_u128(x, q);
            assert_eq!(w.digits(), should_be, "x={} q={}", x, q);
        }
    }

    #[test]
    fn hash() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let q = 2 + (rng.gen_u16() % 110);
            let x = Wire::rand(&mut rng, q);
            let y = x.hashback(Block::from(1u128), q);
            assert!(x != y);
            match y {
                Wire::Mod2 { val } => assert!(u128::from(val) > 0),
                Wire::Mod3 { lsb, msb } => assert!(lsb > 0 && msb > 0),
                Wire::ModN { ds, .. } => assert!(!ds.iter().all(|&y| y == 0)),
            }
        }
    }

    #[test]
    fn negation() {
        let ref mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = Wire::rand(rng, q);
            let xneg = x.negate();
            if q != 2 {
                assert!(x != xneg);
            }
            let y = xneg.negate();
            assert_eq!(x, y);
        }
    }

    #[test]
    fn zero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = 3 + (rng.gen_u16() % 110);
            let z = Wire::zero(q);
            let ds = z.digits();
            assert_eq!(ds, vec![0; ds.len()], "q={}", q);
        }
    }

    #[test]
    fn subzero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = Wire::rand(&mut rng, q);
            let z = Wire::zero(q);
            assert_eq!(x.minus(&x), z);
        }
    }

    #[test]
    fn pluszero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = Wire::rand(&mut rng, q);
            assert_eq!(x.plus(&Wire::zero(q)), x);
        }
    }

    #[test]
    fn arithmetic() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = Wire::rand(&mut rng, q);
            let y = Wire::rand(&mut rng, q);
            assert_eq!(x.cmul(0), Wire::zero(q));
            assert_eq!(x.cmul(q), Wire::zero(q));
            assert_eq!(x.plus(&x), x.cmul(2));
            assert_eq!(x.plus(&x).plus(&x), x.cmul(3));
            assert_eq!(x.negate().negate(), x);
            if q == 2 {
                assert_eq!(x.plus(&y), x.minus(&y));
            } else {
                assert_eq!(x.plus(&x.negate()), Wire::zero(q), "q={}", q);
                assert_eq!(x.minus(&y), x.plus(&y.negate()));
            }
            let mut w = x.clone();
            let z = w.plus(&y);
            w.plus_eq(&y);
            assert_eq!(w, z);

            w = x.clone();
            w.cmul_eq(2);
            assert_eq!(x.plus(&x), w);

            w = x.clone();
            w.negate_eq();
            assert_eq!(x.negate(), w);
        }
    }

    #[test]
    fn ndigits_correct() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = Wire::rand(&mut rng, q);
            assert_eq!(x.digits().len(), util::digits_per_u128(q));
        }
    }

    #[test]
    fn parallel_hash() {
        let n = 1000;
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let ws = (0..n).map(|_| Wire::rand(&mut rng, q)).collect_vec();

        let hashes = crossbeam::scope(|scope| {
            let hs = ws
                .iter()
                .map(|w| scope.spawn(move |_| w.hash(Block::default())))
                .collect_vec();
            hs.into_iter().map(|h| h.join().unwrap()).collect_vec()
        })
        .unwrap();

        let should_be = ws.iter().map(|w| w.hash(Block::default())).collect_vec();

        assert_eq!(hashes, should_be);
    }
}
