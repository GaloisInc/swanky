//! Defines a block as a 128-bit value, and implements block-related functions.

use crate::Aes256;
use curve25519_dalek::ristretto::RistrettoPoint;
use std::hash::Hash;
use subtle::ConditionallySelectable;
use vectoreyes::{SimdBase, SimdBase8, U64x2, U8x16};

// TODO: it might make sense to eliminate this type, in favor of using vectoreyes natively.
/// A 128-bit chunk.
#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    bytemuck::Pod,
    bytemuck::Zeroable,
    bytemuck::TransparentWrapper,
)]
#[repr(transparent)]
pub struct Block(pub U8x16);

impl Block {
    /// Carryless multiplication.
    ///
    /// This code is adapted from the EMP toolkit's implementation.
    #[inline]
    pub fn clmul(self, rhs: Self) -> (Self, Self) {
        let x = U64x2::from(self.0);
        let y = U64x2::from(rhs.0);
        let zero = x.carryless_mul::<false, false>(y);
        let one = x.carryless_mul::<true, false>(y);
        let two = x.carryless_mul::<false, true>(y);
        let three = x.carryless_mul::<true, true>(y);
        let tmp: U8x16 = (one ^ two).into();
        let ll = tmp.shift_bytes_left::<8>();
        let rl = tmp.shift_bytes_right::<8>();
        let x = U8x16::from(zero) ^ ll;
        let y = U8x16::from(three) ^ rl;
        (Block(x), Block(y))
    }

    /// Hash an elliptic curve point `pt` and tweak `tweak`.
    ///
    /// Computes the hash by computing `E_{pt}(tweak)`, where `E` is AES-256.
    #[inline]
    pub fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Self {
        let k = pt.compress();
        let c = Aes256::new(k.as_bytes());
        c.encrypt(Block::from(tweak))
    }

    /// Return the least significant bit.
    #[inline]
    pub fn lsb(&self) -> bool {
        (self.0.extract::<0>() & 1) != 0
    }
    /// Set the least significant bit.
    #[inline]
    pub fn set_lsb(&self) -> Block {
        Block(self.0 | U8x16::set_lo(1))
    }
    /// Flip all bits.
    #[inline]
    pub fn flip(&self) -> Self {
        Block(self.0 ^ U64x2::broadcast(u64::MAX).into())
    }

    /// Try to create a `Block` from a slice of bytes. The slice must have exactly 16 bytes.
    #[inline]
    pub fn try_from_slice(bytes_slice: &[u8]) -> Option<Self> {
        if bytes_slice.len() != 16 {
            return None;
        }
        let mut bytes = [0; 16];
        bytes[..16].clone_from_slice(&bytes_slice[..16]);
        Some(Block::from(bytes))
    }
}

impl Ord for Block {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u128::from(*self).cmp(&u128::from(*other))
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(u128::from(*self).cmp(&u128::from(*other)))
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl ConditionallySelectable for Block {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Block(U8x16::conditional_select(&a.0, &b.0, choice))
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        bytemuck::bytes_of(&self.0)
    }
}
impl AsMut<[u8]> for Block {
    fn as_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(&mut self.0)
    }
}

impl rand::distributions::Distribution<Block> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::from(rng.gen::<u128>())
    }
}

impl From<Block> for u128 {
    #[inline]
    fn from(m: Block) -> u128 {
        #[cfg(target_endian = "little")]
        {
            bytemuck::cast(m.0)
        }
        #[cfg(target_endian = "big")]
        {
            u128::from(m.0.extract::<0>()) | (u128::from(m.0.extract::<1>()) << 64)
        }
    }
}

impl From<u128> for Block {
    #[inline]
    fn from(m: u128) -> Self {
        Block(bytemuck::cast(m))
    }
}

impl From<Block> for U8x16 {
    #[inline]
    fn from(m: Block) -> U8x16 {
        m.0
    }
}

impl From<U8x16> for Block {
    #[inline]
    fn from(m: U8x16) -> Self {
        Block(m)
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(m: Block) -> [u8; 16] {
        U8x16::from(m.0).as_array()
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(m: [u8; 16]) -> Self {
        Block(U8x16::from(m).into())
    }
}

impl std::ops::BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Block(self.0 ^ rhs.0)
    }
}

impl std::ops::BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl std::ops::BitAnd for Block {
    type Output = Block;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Block(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for Block {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct Helperb {
    pub block: [u8; 16],
}

#[cfg(feature = "serde")]
impl Serialize for Block {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let helper = Helperb {
            block: <[u8; 16]>::from(*self),
        };
        helper.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helperb::deserialize(deserializer)?;
        Ok(Block::from(helper.block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flip() {
        let x = rand::random::<Block>();
        let y = x.flip().flip();
        assert_eq!(x, y);
    }

    #[test]
    fn test_conversion() {
        let x = rand::random::<u128>();
        let x_ = u128::from(Block::from(x));
        assert_eq!(x, x_);
    }
}
