//! Low-level operations on wire-labels, the basic building block of garbled circuits.

use crate::{fancy::HasModulus, util};
use fancy_garbling_base_conversion as base_conversion;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{Block, AES_HASH};
use subtle::ConditionallySelectable;
use vectoreyes::array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize};

#[cfg(feature = "serde")]
use crate::errors::{ModQDeserializationError, WireDeserializationError};

mod npaths_tab;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// The core wire-label type.
pub enum AllWire {
    /// Modulo2 Wire
    Mod2(WireMod2),

    /// Modulo3 Wire
    Mod3(WireMod3),

    /// Modulo q Wire: 3 < q < 2^16
    ModN(WireModQ),
}

/// Batch hashing of wires
pub fn hash_wires<const Q: usize, W: WireLabel>(wires: [&W; Q], tweak: Block) -> [Block; Q]
where
    ArrayUnrolledOps: UnrollableArraySize<Q>,
{
    let batch = wires.array_map(|x| x.as_block());
    AES_HASH.tccr_hash_many(tweak, batch)
}

/// Marker trait indicating an arithmetic wire
pub trait ArithmeticWire: Clone {}

/// Trait implementing a wire that can be used for secure computation
/// via garbled circuits
pub trait WireLabel: Clone + HasModulus {
    /// Get the digits of the wire
    fn digits(&self) -> Vec<u16>;

    /// Pack the wire into a `Block`.
    fn as_block(&self) -> Block;

    /// Get the color digit of the wire.
    fn color(&self) -> u16;

    /// Add another wire digit-wise into this one. Assumes that both wires have
    /// the same modulus.
    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self;

    /// Multiply each digit by a constant `c mod q`.
    fn cmul_eq(&mut self, c: u16) -> &mut Self;

    /// Negate all the digits mod q.
    fn negate_eq(&mut self) -> &mut Self;

    /// Pack the wire into a `Block`.
    fn from_block(inp: Block, q: u16) -> Self;

    /// The zero wire with modulus `q`
    fn zero(q: u16) -> Self;

    /// Get a random wire label mod `q`, with the first digit set to `1`
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self;

    /// Get a random wire `mod q`.
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self;

    /// Subroutine of hashback that converts the hash block into a valid wire of the given
    /// modulus. Also useful when batching hashes ahead of time for later conversion.
    fn hash_to_mod(hash: Block, q: u16) -> Self;

    /// Compute the hash of this wire, converting the result back to a wire.
    ///
    /// Uses fixed-key AES.
    fn hashback(&self, tweak: Block, q: u16) -> Self {
        let hash = self.hash(tweak);
        Self::hash_to_mod(hash, q)
    }

    /// Negate all the digits `mod q`, consuming it for chained computations.
    fn negate_mov(mut self) -> Self {
        self.negate_eq();
        self
    }

    /// Multiply each digit by a constant `c mod q`, consuming it for chained computations.
    fn cmul_mov(mut self, c: u16) -> Self {
        self.cmul_eq(c);
        self
    }

    /// Multiply each digit by a constant `c mod q`, returning a new wire.
    fn cmul(&self, c: u16) -> Self {
        self.clone().cmul_mov(c)
    }

    /// Add another wire into this one, consuming it for chained computations.
    fn plus_mov(mut self, other: &Self) -> Self {
        self.plus_eq(other);
        self
    }

    /// Add two wires digit-wise, returning a new wire.
    fn plus(&self, other: &Self) -> Self {
        self.clone().plus_mov(other)
    }

    /// Negate all the digits `mod q`, returning a new wire.
    fn negate(&self) -> Self {
        self.clone().negate_mov()
    }

    /// Subtract a wire from this one, consuming it for chained computations.
    fn minus_mov(mut self, other: &Self) -> Self {
        self.minus_eq(other);
        self
    }

    /// Subtract two wires, returning the result.
    fn minus(&self, other: &Self) -> Self {
        self.clone().minus_mov(other)
    }

    /// Subtract a wire from this one.
    fn minus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        self.plus_eq(&other.negate());
        self
    }

    /// Compute the hash of this wire.
    ///
    /// Uses fixed-key AES.
    #[inline(never)]
    fn hash(&self, tweak: Block) -> Block {
        AES_HASH.tccr_hash(tweak, self.as_block())
    }
}

/// Representation of a `mod-2` wire.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod2 {
    /// A 128-bit value.
    val: Block,
}

impl ConditionallySelectable for WireMod2 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        WireMod2::from_block(
            Block::conditional_select(&a.as_block(), &b.as_block(), choice),
            2,
        )
    }
}

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
    type Error = WireDeserializationError;

    fn try_from(wire: UntrustedWireMod3) -> Result<Self, Self::Error> {
        if wire.lsb & wire.msb != 0 {
            return Err(Self::Error::InvalidWireMod3);
        }
        Ok(WireMod3 {
            lsb: wire.lsb,
            msb: wire.msb,
        })
    }
}

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
    type Error = WireDeserializationError;

    fn try_from(wire: UntrustedWireModQ) -> Result<Self, Self::Error> {
        // Modulus must be at least 2
        if wire.q < 2 {
            return Err(Self::Error::InvalidWireModQ(
                ModQDeserializationError::BadModulus(wire.q),
            ));
        }

        // Check correct length and make sure all values are less than the modulus
        let expected_len = util::digits_per_u128(wire.q);
        let given_len = wire.ds.len();
        if given_len != expected_len {
            return Err(Self::Error::InvalidWireModQ(
                ModQDeserializationError::InvalidDigitsLength {
                    got: given_len,
                    needed: expected_len,
                },
            ));
        }
        if let Some(i) = wire.ds.iter().position(|&x| x >= wire.q) {
            return Err(Self::Error::InvalidWireModQ(
                ModQDeserializationError::DigitTooLarge {
                    digit: wire.ds[i],
                    modulus: wire.q,
                },
            ));
        }
        Ok(WireModQ {
            q: wire.q,
            ds: wire.ds,
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
    lsb: u64,
    /// The most-significant bits of each `mod-3` element.
    msb: u64,
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
    ds: Vec<u16>,
}

impl HasModulus for WireMod2 {
    fn modulus(&self) -> u16 {
        2
    }
}

impl HasModulus for WireMod3 {
    fn modulus(&self) -> u16 {
        3
    }
}

impl HasModulus for WireModQ {
    fn modulus(&self) -> u16 {
        self.q
    }
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

impl WireLabel for AllWire {
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand_delta(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand_delta(rng, q)),
            _ => AllWire::ModN(WireModQ::rand_delta(rng, q)),
        }
    }

    fn digits(&self) -> Vec<u16> {
        match &self {
            AllWire::Mod2(x) => x.digits(),
            AllWire::Mod3(x) => x.digits(),
            AllWire::ModN(x) => x.digits(),
        }
    }

    fn as_block(&self) -> Block {
        match &self {
            AllWire::Mod2(x) => x.as_block(),
            AllWire::Mod3(x) => x.as_block(),
            AllWire::ModN(x) => x.as_block(),
        }
    }
    fn color(&self) -> u16 {
        match &self {
            AllWire::Mod2(x) => x.color(),
            AllWire::Mod3(x) => x.color(),
            AllWire::ModN(x) => x.color(),
        }
    }
    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        match (&mut *self, other) {
            (AllWire::Mod2(ref mut x), AllWire::Mod2(y)) => {
                x.plus_eq(y);
            }
            (AllWire::Mod3(ref mut x), AllWire::Mod3(y)) => {
                x.plus_eq(y);
            }
            (AllWire::ModN(ref mut x), AllWire::ModN(y)) => {
                x.plus_eq(y);
            }
            _ => {
                panic!(
                    "[AllWire::plus_eq] unequal moduli: {}, {}!",
                    self.modulus(),
                    other.modulus()
                )
            }
        };
        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        match &mut *self {
            AllWire::Mod2(ref mut x) => {
                x.cmul_eq(c);
            }
            AllWire::Mod3(ref mut x) => {
                x.cmul_eq(c);
            }
            AllWire::ModN(ref mut x) => {
                x.cmul_eq(c);
            }
        };
        self
    }
    fn negate_eq(&mut self) -> &mut Self {
        match &mut *self {
            AllWire::Mod2(ref mut x) => {
                x.negate_eq();
            }
            AllWire::Mod3(ref mut x) => {
                x.negate_eq();
            }
            AllWire::ModN(ref mut x) => {
                x.negate_eq();
            }
        };
        self
    }
    fn from_block(inp: Block, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::from_block(inp, q)),
            3 => AllWire::Mod3(WireMod3::from_block(inp, q)),
            _ => AllWire::ModN(WireModQ::from_block(inp, q)),
        }
    }

    fn zero(q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::zero(q)),
            3 => AllWire::Mod3(WireMod3::zero(q)),
            _ => AllWire::ModN(WireModQ::zero(q)),
        }
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand(rng, q)),
            _ => AllWire::ModN(WireModQ::rand(rng, q)),
        }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q == 3 {
            AllWire::Mod3(WireMod3::encode_block_mod3(hash))
        } else {
            Self::from_block(hash, q)
        }
    }
}

impl WireMod3 {
    /// We have to convert `block` into a valid `Mod3` encoding.
    ///
    /// We do this by computing the `Mod3` digits using `_unrank`,
    /// and then map these to a `Mod3` encoding.
    fn encode_block_mod3(block: Block) -> Self {
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

impl WireLabel for WireMod2 {
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand_delta] Expected modulo 2. Got {}", q);
        }
        let mut w = Self::rand(rng, q);
        w.val = w.val.set_lsb();
        w
    }

    fn digits(&self) -> Vec<u16> {
        (0..128)
            .map(|i| ((u128::from(self.val) >> i) as u16) & 1)
            .collect()
    }

    fn as_block(&self) -> Block {
        self.val
    }

    fn color(&self) -> u16 {
        self.val.lsb() as u16
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        self.val ^= other.val;
        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        if c & 1 == 0 {
            self.val = Block::default();
        }
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        // Do nothing. Additive inverse is a no-op for mod 2.
        self
    }

    fn from_block(inp: Block, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::from_block] Expected modulo 2. Got {}", q);
        }
        Self { val: inp }
    }

    fn zero(q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::zero] Expected modulo 2. Got {}", q);
        }
        Self::default()
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand] Expected modulo 2. Got {}", q);
        }

        Self { val: rng.gen() }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::hash_to_mod] Expected modulo 2. Got {}", q);
        }
        Self::from_block(hash, q)
    }
}

impl WireLabel for WireMod3 {
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand_delta] Expected modulo 3. Got {}", q);
        }
        let mut w = Self::rand(rng, 3);
        w.lsb |= 1;
        w.msb &= 0xFFFF_FFFF_FFFF_FFFE;
        w
    }

    fn digits(&self) -> Vec<u16> {
        (0..64)
            .map(|i| (((self.lsb >> i) as u16) & 1) & ((((self.msb >> i) as u16) & 1) << 1))
            .collect()
    }

    fn as_block(&self) -> Block {
        Block::from(((self.msb as u128) << 64) | (self.lsb as u128))
    }

    fn color(&self) -> u16 {
        let color = (((self.msb & 1) as u16) << 1) | ((self.lsb & 1) as u16);
        debug_assert_ne!(color, 3);
        color
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        let a1 = &mut self.lsb;
        let a2 = &mut self.msb;
        let b1 = other.lsb;
        let b2 = other.msb;

        let t = (*a1 | b2) ^ (*a2 | b1);
        let c1 = (*a2 | b2) ^ t;
        let c2 = (*a1 | b1) ^ t;
        *a1 = c1;
        *a2 = c2;
        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        match c {
            0 => {
                self.msb = 0;
                self.lsb = 0;
            }
            1 => {}
            2 => {
                std::mem::swap(&mut self.lsb, &mut self.msb);
            }
            c => {
                self.cmul_eq(c % 3);
            }
        }
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        // Negation just involves swapping `lsb` and `msb`.
        std::mem::swap(&mut self.lsb, &mut self.msb);
        self
    }

    fn from_block(inp: Block, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::from_block] Expected mod 3. Got mod {}", q)
        }
        let inp = u128::from(inp);
        let lsb = inp as u64;
        let msb = (inp >> 64) as u64;
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn zero(q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::zero] Expected modulo 3. Got {}", q);
        }
        Self::default()
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand] Expected mod 3. Got mod {}", q)
        }
        let mut lsb = 0u64;
        let mut msb = 0u64;
        for (i, v) in (0..64).map(|_| rng.gen::<u8>() % 3).enumerate() {
            lsb |= ((v & 1) as u64) << i;
            msb |= (((v >> 1) & 1) as u64) << i;
        }
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::hash_to_mod] Expected mod 3. Got mod {}", q)
        }
        Self::encode_block_mod3(hash)
    }
}

impl WireLabel for WireModQ {
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
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

    fn digits(&self) -> Vec<u16> {
        self.ds.clone()
    }

    fn as_block(&self) -> Block {
        Block::from(util::from_base_q(&self.ds, self.q))
    }

    fn color(&self) -> u16 {
        let color = self.ds[0];
        debug_assert!(color < self.q);
        color
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        let xs = &mut self.ds;
        let ys = &other.ds;
        let q = self.q;

        // Assuming modulus has to be the same here
        // Will enforce by type system
        //debug_assert_eq!(, ymod);
        debug_assert_eq!(xs.len(), ys.len());
        xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });

        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        let q = self.q;
        self.ds
            .iter_mut()
            .for_each(|d| *d = (*d as u32 * c as u32 % q as u32) as u16);
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        let q = self.q;
        self.ds.iter_mut().for_each(|d| {
            if *d > 0 {
                *d = q - *d;
            } else {
                *d = 0;
            }
        });
        self
    }
    fn from_block(inp: Block, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::from_block] Modulus must be at least 2. Got {}",
                q
            );
        }
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
            _unrank(u128::from(inp), q)
        } else if base_conversion::lookup_defined_for_mod(q) {
            _from_block_lookup(inp, q)
        } else {
            // If all else fails, do unrank using naive division.
            _unrank(u128::from(inp), q)
        };
        Self { q, ds }
    }
    /// Unpack the wire represented by a `Block` with modulus `q`. Assumes that
    /// the block was constructed through the `AllWire` API.
    fn zero(q: u16) -> Self {
        if q < 2 {
            panic!("[WireModQ::zero] Modulus must be at least 2. Got {}", q);
        }
        Self {
            q,
            ds: vec![0; util::digits_per_u128(q)],
        }
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q < 2 {
            panic!("[WireModQ::rand] Modulus must be at least 2. Got {}", q);
        }
        let ds = (0..util::digits_per_u128(q))
            .map(|_| rng.gen::<u16>() % q)
            .collect();
        Self { q, ds }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::hash_to_mod] Modulus must be at least 2. Got {}",
                q
            );
        }
        Self::from_block(hash, q)
    }
}

// Helpers for mod 3 and q
fn _from_block_lookup(inp: Block, q: u16) -> Vec<u16> {
    debug_assert!(q < 256);
    debug_assert!(base_conversion::lookup_defined_for_mod(q));
    let bytes: [u8; 16] = inp.into();
    // The digits in position 15 will be the longest, so we can use stateful
    // (fast) base `q` addition.
    let mut ds = base_conversion::lookup_digits_mod_at_position(bytes[15], q, 15).to_vec();
    for i in 0..15 {
        let cs = base_conversion::lookup_digits_mod_at_position(bytes[i], q, i);
        util::base_q_add_eq(&mut ds, cs, q);
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

impl ArithmeticWire for WireMod3 {}
impl ArithmeticWire for WireModQ {}
impl ArithmeticWire for AllWire {}

////////////////////////////////////////////////////////////////////////////////
// tests
//
//
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    #[test]
    fn packing() {
        let rng = &mut thread_rng();
        for q in 2..256 {
            for _ in 0..1000 {
                let w = AllWire::rand(rng, q);
                assert_eq!(w, AllWire::from_block(w.as_block(), q));
            }
        }
    }

    #[test]
    fn base_conversion_lookup_method() {
        let rng = &mut thread_rng();
        for _ in 0..1000 {
            let q = 5 + (rng.gen_u16() % 110);
            let x = rng.gen_u128();
            let w = AllWire::from_block(Block::from(x), q);
            let should_be = util::as_base_q_u128(x, q);
            assert_eq!(w.digits(), should_be, "x={} q={}", x, q);
        }
    }

    #[test]
    fn hash() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let q = 2 + (rng.gen_u16() % 110);
            let x = AllWire::rand(&mut rng, q);
            let y = x.hashback(Block::from(1u128), q);
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
        let rng = &mut thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(rng, q);
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
            let z = AllWire::zero(q);
            let ds = z.digits();
            assert_eq!(ds, vec![0; ds.len()], "q={}", q);
        }
    }

    #[test]
    fn subzero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            let z = AllWire::zero(q);
            assert_eq!(x.minus(&x), z);
        }
    }

    #[test]
    fn pluszero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            assert_eq!(x.plus(&AllWire::zero(q)), x);
        }
    }

    #[test]
    fn arithmetic() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            let y = AllWire::rand(&mut rng, q);
            assert_eq!(x.cmul(0), AllWire::zero(q));
            assert_eq!(x.cmul(q), AllWire::zero(q));
            assert_eq!(x.plus(&x), x.cmul(2));
            assert_eq!(x.plus(&x).plus(&x), x.cmul(3));
            assert_eq!(x.negate().negate(), x);
            if q == 2 {
                assert_eq!(x.plus(&y), x.minus(&y));
            } else {
                assert_eq!(x.plus(&x.negate()), AllWire::zero(q), "q={}", q);
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
            let x = AllWire::rand(&mut rng, q);
            assert_eq!(x.digits().len(), util::digits_per_u128(q));
        }
    }

    #[test]
    fn parallel_hash() {
        let n = 1000;
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let ws = (0..n).map(|_| AllWire::rand(&mut rng, q)).collect_vec();

        let mut handles = Vec::new();
        for w in ws.iter() {
            let w_ = w.clone();
            let h = std::thread::spawn(move || w_.hash(Block::default()));
            handles.push(h);
        }
        let hashes = handles.into_iter().map(|h| h.join().unwrap()).collect_vec();

        let should_be = ws.iter().map(|w| w.hash(Block::default())).collect_vec();

        assert_eq!(hashes, should_be);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_mod2() {
        let mut rng = thread_rng();
        let w = WireMod2::rand(&mut rng, 2);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod2 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_allwire() {
        let mut rng = thread_rng();
        for q in 2..16 {
            let w = AllWire::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: AllWire = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_mod3() {
        let mut rng = thread_rng();
        let w = WireMod3::rand(&mut rng, 3);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod3 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_mod3() {
        let mut rng = thread_rng();
        let mut w = WireMod3::rand(&mut rng, 3);

        // lsb and msb can't both be set
        w.lsb |= 1;
        w.msb |= 1;
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: Result<WireMod3, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_modQ() {
        let mut rng = thread_rng();

        for _ in 0..16 {
            let q: u16 = rng.gen();
            let w = WireModQ::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: WireModQ = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_mod() {
        let mut rng = thread_rng();
        let q: u16 = rng.gen();

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
