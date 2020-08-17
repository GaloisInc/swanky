//! This module defines finite fields.

use generic_array::{ArrayLength, GenericArray};
use rand_core::RngCore;
use std::{
    fmt::Debug,
    hash::Hash,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Types that implement this trait are finite field elements.
pub trait FiniteField:
    'static
    + Hash
    + Debug
    + PartialEq
    + Eq
    + ConstantTimeEq
    + ConditionallySelectable
    + Clone
    + Copy
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Neg<Output = Self>
    + std::iter::Sum
{
    /// The number of bytes in the byte representation for this field element.
    type ByteReprLen: ArrayLength<u8>;
    /// The error that can result from trying to decode an invalid byte sequence.
    type FromBytesError: std::error::Error + Send + Sync + 'static;
    /// Deserialize a field element from a byte array.
    ///
    /// NOTE: for security purposes, this function will accept exactly one byte sequence for each
    /// field element.
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError>;
    /// Serialize a field element into a byte array.
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen>;

    /// Generate a random field element.
    fn random<R: RngCore>(rng: &mut R) -> Self;

    /// The order of the multiplicative group
    // TODO: we'll want a better number type than u128 if the fields get bigger.
    const MULTIPLICATIVE_GROUP_ORDER: u128;
    /// Return a generator for the multiplicative group.
    fn generator() -> Self;
    /// Return the additive identity element.
    fn zero() -> Self;
    /// Return the multiplicative identity element.
    fn one() -> Self;

    /// Compute the multiplicative inverse of self.
    ///
    /// # Panics
    /// This function will panic if *self == Self::zero()
    fn inverse(&self) -> Self {
        if *self == Self::zero() {
            panic!("Zero cannot be inverted");
        }
        // NOTE: this only works for GF(p^n)
        self.pow(Self::MULTIPLICATIVE_GROUP_ORDER - 1)
    }

    /// Computing `pow` using Montgomery's ladder technique.
    fn pow(&self, n: u128) -> Self {
        let mut r0 = Self::one();
        let mut r1 = *self;
        for i in (0..128).rev() {
            // This is equivalent to the following code, but constant-time:
            if n & (1 << i) == 0 {
                r1.mul_assign(r0);
                r0.mul_assign(r0);
            } else {
                r0.mul_assign(r1);
                r1.mul_assign(r1);
            }
            /*let bit_is_high = Choice::from((n & (1 << i) != 0) as u8);
            let operand = Self::conditional_select(&r0, &r1, bit_is_high);
            r0 *= operand;
            r1 *= operand;*/
        }
        r0
    }
}

#[cfg(test)]
#[macro_use]
mod test_utils;

mod fp;
pub use fp::{BiggerThanModulus, Fp};

mod gf_2_128;
pub use gf_2_128::{Gf128, Gf128BytesDeserializationCannotFail};
