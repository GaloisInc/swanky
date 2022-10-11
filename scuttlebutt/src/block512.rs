//! Defines a 512-bit value.
use crate::Block;
use std::hash::Hash;

/// A 512-bit value.
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Hash,
    bytemuck::Pod,
    bytemuck::Zeroable,
    bytemuck::TransparentWrapper,
)]
#[repr(transparent)]
pub struct Block512(pub(crate) [Block; 4]);

impl Block512 {
    /// Return the first `n` bytes, where `n` must be `<= 64`.
    #[inline]
    pub fn prefix(&self, n: usize) -> &[u8] {
        &self.as_ref()[0..n]
    }

    /// Return the first `n` bytes as mutable, where `n` must be `<= 64`.
    #[inline]
    pub fn prefix_mut(&mut self, n: usize) -> &mut [u8] {
        &mut self.as_mut()[0..n]
    }
}

impl AsMut<[u8]> for Block512 {
    fn as_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(self)
    }
}

impl AsRef<[u8]> for Block512 {
    fn as_ref(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

impl std::ops::BitXor for Block512 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        let b0 = self.0[0] ^ rhs.0[0];
        let b1 = self.0[1] ^ rhs.0[1];
        let b2 = self.0[2] ^ rhs.0[2];
        let b3 = self.0[3] ^ rhs.0[3];
        Self([b0, b1, b2, b3])
    }
}

impl std::ops::BitXorAssign for Block512 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl std::fmt::Display for Block512 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl rand::distributions::Distribution<Block512> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block512 {
        let b1 = rng.gen::<Block>();
        let b2 = rng.gen::<Block>();
        let b3 = rng.gen::<Block>();
        let b4 = rng.gen::<Block>();
        Block512([b1, b2, b3, b4])
    }
}

impl From<Block512> for [u32; 16] {
    #[inline]
    fn from(m: Block512) -> [u32; 16] {
        bytemuck::cast(m)
    }
}

impl From<Block512> for [Block; 4] {
    #[inline]
    fn from(m: Block512) -> [Block; 4] {
        m.0
    }
}

impl<'a> From<&'a Block512> for &'a [Block; 4] {
    #[inline]
    fn from(m: &Block512) -> &[Block; 4] {
        &m.0
    }
}

impl<'a> From<&'a mut Block512> for &'a mut [Block; 4] {
    #[inline]
    fn from(m: &mut Block512) -> &mut [Block; 4] {
        &mut m.0
    }
}

impl<'a> From<&'a mut Block512> for &'a mut [u8; 64] {
    #[inline]
    fn from(m: &'a mut Block512) -> Self {
        bytemuck::cast_mut(m)
    }
}

impl From<[Block; 4]> for Block512 {
    #[inline]
    fn from(m: [Block; 4]) -> Block512 {
        Block512(m)
    }
}

impl From<[u8; 64]> for Block512 {
    #[inline]
    fn from(m: [u8; 64]) -> Block512 {
        bytemuck::cast(m)
    }
}

impl TryFrom<&[u8]> for Block512 {
    type Error = core::array::TryFromSliceError;
    #[inline]
    fn try_from(u: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 512 / 8]>::try_from(u)?;
        Ok(bytemuck::cast(bytes))
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct Helper {
    pub blocks: [Block; 4],
}

#[cfg(feature = "serde")]
impl Serialize for Block512 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = Helper { blocks: self.0 };
        helper.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Block512 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helper::deserialize(deserializer)?;
        Ok(Block512::from(helper.blocks))
    }
}
