//! VectorEyes is a (almost entirely) safe wrapper library around vectorized operations.
//!
//! # Backends
//! VectorEyes chooses what backend to execute vector operations with at compile-time.
//! ## AVX2
//! CPUs that support the `AVX`, `AVX2`, `SSE4.1`, `AES`, `SSE4.2`, and `PCLMULQDQ` features will
//! use the `AVX2` backend.
//!
//! In addition, we have embedded specific latency numbers for:
//!
//! * `skylake`
//! * `skylake-avx512`
//! * `cascadelake`
//! * `znver1`
//! * `znver2`
//! * `znver3`
//!
//! As a result, `vectoreyes` will be more efficient on these platforms. You can add specific
//! latency numbers for more targets in `avx2.py`.
//! ## Scalar
//! At the moment, this is the only alternative to the `AVX2` backend. It is not particularly
//! optimized.
//!
//! # Cargo Configuration
//! ## Native CPU Setup
//! Compile on the machine that you'll be running your code on, and add the
//! following to your `.cargo/config` file:
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! rustdocflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! ```
//! ## Specific CPU Selection
//! If you want to compile for some specific CPU
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! rustdocflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! ```
//! ## Maximal Compatibility
//! If you do not put any of the above in your `.cargo/config` file, vectoreyes will always use its
//! `scalar` backend, which does not use vector instructions.
//!
//! **NOTE:** many functions are currently missing from this library. Please
//! consult the Intel documentation to see if a non-implemented intrinsic would
//! more directly accomplish your goal, and we can add it!

// TODO: support more fine-grained cpu features?

use std::ops::*;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MicroArchitecture {
    Skylake,
    SkylakeAvx512,
    CascadeLake,
    AmdZenVer1,
    AmdZenVer2,
    AmdZenVer3,
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VectorBackend {
    Scalar,
    Avx2 {
        micro_architecture: MicroArchitecture,
    },
}

/// A scalar that can live in the lane of a vector.
pub trait Scalar:
    'static
    + std::fmt::Debug
    + num_traits::PrimInt
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + num_traits::WrappingMul
    + subtle::ConstantTimeEq
    + subtle::ConditionallySelectable
{
    /// A scalar of the same width as this scalar, but signed.
    type Signed: Scalar;
    /// A scalar of the same width as this scalar, but unsigned.
    type Unsigned: Scalar;

    /// A scalar of the same sign as this scalar, but with width 8.
    type SameSign8: Scalar<Signed = i8, Unsigned = u8>;
    /// A scalar of the same sign as this scalar, but with width 16.
    type SameSign16: Scalar<Signed = i16, Unsigned = u16>;
    /// A scalar of the same sign as this scalar, but with width 32.
    type SameSign32: Scalar<Signed = i32, Unsigned = u32>;
    /// A scalar of the same sign as this scalar, but with width 64.
    type SameSign64: Scalar<Signed = i64, Unsigned = u64>;
}
macro_rules! scalar_impls {
    ($(($s:ty, $u:ty)),*) => {$(
        impl Scalar for $s {
            type Signed = $s;
            type Unsigned = $u;

            type SameSign8 = i8;
            type SameSign16 = i16;
            type SameSign32 = i32;
            type SameSign64 = i64;
        }
        impl Scalar for $u {
            type Signed = $s;
            type Unsigned = $u;

            type SameSign8 = u8;
            type SameSign16 = u16;
            type SameSign32 = u32;
            type SameSign64 = u64;
        }
    )*};
}
scalar_impls!((i64, u64), (i32, u32), (i16, u16), (i8, u8));
/// A vector equivalent to `[T; Self::Lanes]`.
///
/// Note that each implemented method shows an equivalent scalar implementation.
///
/// # Effects of Signedness on shift operations
/// When `Scalar` is _signed_, this will shift in sign bits, as opposed to zeroes.
pub trait SimdBase:
    'static
    + Sized
    + Clone
    + Copy
    + Sync
    + Send
    + std::fmt::Debug
    + PartialEq
    + Eq
    + Default
    + bytemuck::Pod
    + bytemuck::Zeroable
    + BitXor
    + BitXorAssign
    + BitOr
    + BitOrAssign
    + BitAnd
    + BitAndAssign
    + AddAssign
    + Add
    + SubAssign
    + Sub
    + ShlAssign<u64>
    + Shl<u64, Output = Self>
    + ShrAssign<u64>
    + Shr<u64, Output = Self>
    + ShlAssign<Self>
    + Shl<Self, Output = Self>
    + ShrAssign<Self>
    + Shr<Self, Output = Self>
    + subtle::ConstantTimeEq
    + subtle::ConditionallySelectable
{
    /// The number of elements of this vector.
    ///
    /// **Note:** this number is _not_ the number of 128-bit lanes in this vector.
    const LANES: usize;

    /// The equivalent array type of this vector.
    type Array: 'static
        + Sized
        + Clone
        + Copy
        + Sync
        + Send
        + std::fmt::Debug
        + bytemuck::Pod
        + bytemuck::Zeroable
        + PartialEq
        + Eq
        + Default
        + std::hash::Hash
        + AsRef<[Self::Scalar]>
        + From<Self>
        + Into<Self>;

    /// The scalar that this value holds.
    type Scalar: Scalar;
    /// The signed version of this vector.
    type Signed: SimdBase<Scalar = <<Self as SimdBase>::Scalar as Scalar>::Signed>
        + From<Self>
        + Into<Self>;
    /// The unsigned version of this vector.
    type Unsigned: SimdBase<Scalar = <<Self as SimdBase>::Scalar as Scalar>::Unsigned>
        + From<Self>
        + Into<Self>;

    const ZERO: Self;
    fn is_zero(&self) -> bool;

    /// Create a new vector by setting element 0 to `value`, and the rest of the elements to `0`.
    fn set_lo(value: Self::Scalar) -> Self;

    /// Create a new vector by setting every element to `value`.
    fn broadcast(value: Self::Scalar) -> Self;

    type BroadcastLoInput: SimdBase<Scalar = Self::Scalar>;
    /// Create a vector by setting every element to element 0 of `of`.
    fn broadcast_lo(of: Self::BroadcastLoInput) -> Self;

    /// Get the `I`-th element of this vector
    fn extract<const I: usize>(&self) -> Self::Scalar;

    /// Convert the vector to an array.
    #[inline(always)]
    fn as_array(&self) -> Self::Array {
        (*self).into()
    }

    /// Shift each element left by `BITS`.
    fn shift_left<const BITS: usize>(&self) -> Self;
    /// Shift each element right by `BITS`.
    /// # Effects of Signedness
    /// When `T` is _signed_, this will shift in sign bits, as opposed to zeroes.
    fn shift_right<const BITS: usize>(&self) -> Self;

    /// Compute `self & (! other)`.
    fn and_not(&self, other: Self) -> Self;

    /// Create a vector where each element is all 1's if the elements are equal, and all 0's otherwise.
    fn cmp_eq(&self, other: Self) -> Self;
    /// Create a vector where each element is all 1's if the element of `self` is greater than the
    /// corresponding element of `other`, and all 0's otherwise.
    fn cmp_gt(&self, other: Self) -> Self;

    /// Interleave the elements of the low half of `self` and `other`
    fn unpack_lo(&self, other: Self) -> Self;
    /// Interleave the elements of the high half of `self` and `other`
    fn unpack_hi(&self, other: Self) -> Self;

    /// Make a vector consisting of the maximum elements of `self` and other.
    fn max(&self, other: Self) -> Self;
    /// Make a vector consisting of the minimum elements of `self` and other.
    fn min(&self, other: Self) -> Self;
}

pub trait SimdBaseGatherable<IV: SimdBase>: SimdBase {
    /// Construct a vector by accessing values at `base + indices[i]`
    unsafe fn gather(base: *const Self::Scalar, indices: IV) -> Self;
    /// Construct a vector by accessing values at `base + indices[i]`, only if the mask is set.
    unsafe fn gather_masked(base: *const Self::Scalar, indices: IV, mask: Self, src: Self) -> Self;
}

/// A vector containing 4 lanes.
pub trait SimdBase4x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    fn blend<const B3: bool, const B2: bool, const B1: bool, const B0: bool>(
        &self,
        if_true: Self,
    ) -> Self;
}

/// A vector containing 8 lanes.
pub trait SimdBase8x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    fn blend<
        const B7: bool,
        const B6: bool,
        const B5: bool,
        const B4: bool,
        const B3: bool,
        const B2: bool,
        const B1: bool,
        const B0: bool,
    >(
        &self,
        if_true: Self,
    ) -> Self;
}

/// A vector supporting saturating arithmetic on each entry
pub trait SimdSaturatingArithmetic: SimdBase {
    fn saturating_add(&self, other: Self) -> Self;
    fn saturating_sub(&self, other: Self) -> Self;
}

/// A vector containing 8-bit values.
pub trait SimdBase8: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u8, Signed = i8>,
{
    /// Shift within 128-bit lanes.
    fn shift_bytes_left<const AMOUNT: usize>(&self) -> Self;
    /// Shift within 128-bit lanes.
    fn shift_bytes_right<const AMOUNT: usize>(&self) -> Self;
    /// Get the sign/most significant bits of the elements of the vector.
    fn most_significant_bits(&self) -> u32;
}

/// A vector containing 16-bit values.
pub trait SimdBase16: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u16, Signed = i16>,
{
    /// Shuffle within the lower 64-bits of each 128-bit lane.
    fn shuffle_lo<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
    /// Shuffle within the upper 64-bits of each 128-bit lane.
    fn shuffle_hi<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
}

/// A vector containing 32-bit values.
pub trait SimdBase32: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u32, Signed = i32>,
{
    /// Shuffle within 128-bit lanes.
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

/// A vector containing 64-bit values.
pub trait SimdBase64: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Zero out the upper-32 bits of each word, and then perform pairwise multiplication.
    fn mul_lo(&self, other: Self) -> Self;
}

/// A vector containing 4 64-bit values.
pub trait SimdBase4x64: SimdBase64 + SimdBase4x
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Shuffle across 128-bit lanes.
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

// TODO: deprecate the uses of from() everywhere and use traits/functions that make it obvious which
// casts are free and which aren't.

/// Lossily cast a vector by {zero,sign}-extending its values.
pub trait ExtendingCast<T: SimdBase>: SimdBase {
    /// Cast from one vector to another by sign or zero exending the values from the source until it
    /// fills the destination.
    ///
    /// This operation is neccessarily lossy. The lowest-index values in `t` are kept. Other values
    /// are discarded.
    fn extending_cast_from(t: T) -> Self;
}

/// A utility trait you probably won't need to use. See [Simd].
pub trait HasVector<const N: usize>: Scalar {
    type Vector: SimdBase<Scalar = Self>;
}

/// An alternative way of naming SIMD types.
///
/// # Example
/// ```
/// # use vectoreyes::*;
/// type MyVector = Simd<u8, 16>; // The same as U8x16.
/// ```
pub type Simd<T, const N: usize> = <T as HasVector<N>>::Vector;

pub trait AesBlockCipher: 'static + Clone + Sync + Send {
    type Key: 'static + Clone + Sync + Send;

    /// If you don't need to use Aes for decryption, it's faster to only perform key scheduling
    /// for encryption than for both encryption and decryption.
    type EncryptOnly: AesBlockCipher<Key = Self::Key> + From<Self>;

    /// A pre-scheduled Aes block cipher with a compile-time constant key.
    const FIXED_KEY: Self;

    /// Running `encrypt_many` with this many blocks will result in the best performance.
    ///
    /// When using hardware AES instructions, if the AES encrypt instructions all have a
    /// throughput of 1, then this constant will be equal to the instruction latency.
    const BLOCK_COUNT_HINT: usize;

    /// If you need to AES with a particular key, be careful about endianness issues.
    fn new_with_key(key: Self::Key) -> Self;

    #[inline(always)]
    fn encrypt(&self, block: U8x16) -> U8x16 {
        self.encrypt_many([block])[0]
    }
    fn encrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

pub trait AesBlockCipherDecrypt: AesBlockCipher {
    #[inline(always)]
    fn decrypt(&self, block: U8x16) -> U8x16 {
        self.decrypt_many([block])[0]
    }
    fn decrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

pub mod array_utils;
#[allow(clippy::all)]
mod generated;
pub use generated::implementation::*;
