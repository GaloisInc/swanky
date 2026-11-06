#![deny(missing_docs)]
#![allow(unsafe_op_in_unsafe_fn)]
// Because we generate a large volume of code that uses wildcard
// imports, we allow their use in vectoreyes.
#![allow(clippy::wildcard_imports)]
//! VectorEyes is a (almost entirely) safe and cross-platform wrapper library around vectorized
//! operations.
//!
//! While a normal `add` CPU instruction will add two numbers together, a
//! [SIMD/Vectorized](https://en.wikipedia.org/wiki/Single_instruction,_multiple_data) `add`
//! instruction will perform multiple additions from the same instruction. This will amortize the
//! per-instruction cost (e.g. of the CPU decoding the instruction) across all the additions of the
//! single instruction. This can provide large speed boosts on many platforms.
//!
//! Unfortunately, using these operations require using per-platform unsafe intrinsics. To make
//! this easier, VectorEyes provide safe functions which will function identically on all
//! platforms.
//!
//! The core of this crate is vector types (such as [`U64x2`]). You can think of vectors as arrays
//! with some extra SIMD operations on top.
//!
//! Just like arrays vectors have an element type ([`u64`] in the example above), and an element
//! count, frequently referred to as _lanes_ (2 in the above example).
//!
//! In fact, you can freely convert between arrays and vectors!
//!
//! ```
//! # use vectoreyes::*;
//! // These two represent the same thing.
//! let vector_form = U64x2::from([123_u64, 456_u64]);
//! let array_form: [u64; 2] = vector_form.into();
//! ```
//!
//! However, the vector form has _special SIMD powers_! These two functions perform the same
//! operation, but the SIMD variant may[^may_be_faster] take better advantage of the CPU hardware.
//!
//! [^may_be_faster]: As always, only a Sith deals in absolutes. The Rust compiler can, in some
//! cases, employ _autovectorization_ to compile code which doesn't use SIMD operations into code
//! which uses SIMD instructions. Unfortunately, the compiler can't always autovectorize the way we
//! want it to, which is why VectorEyes exists!
//!
//! While normal _bog-standard_ arrays don't implement the `+` operator, our vector types do!
//! Adding two vectors together performs pairwise addition, using (for the vector backends) a
//! single CPU instruction!
//!
//! ```
//! # use vectoreyes::*;
//! fn double_without_simd(arr: [u64; 2]) -> [u64; 2] {
//!     [arr[0] + arr[0], arr[1] + arr[1]]
//! }
//! fn double_with_simd(arr: U64x2) -> U64x2 {
//!     arr + arr
//! }
//! assert_eq!(
//!     U64x2::from(double_without_simd([1, 2])),
//!     double_with_simd(U64x2::from([1, 2])),
//! );
//! ```
//!
//! The documentation for every method on a vector (e.g. [`I64x2::and_not`]) lists the equivalent
//! scalar code, as well as information on how the operation is implemented on each backend.
//!
//! # Vector Sizes
//! There aren't vector types for every conceivable `(type, element count)` pair. Instead, we have
//! vector types that correspond to the vector registers that many CPUs have. Because these
//! registers are 128- or 256-bits wide, we choose vector types which also have this size. For
//! example, there's a [`U64x2`] type and a [`U32x4`] type, since both are 128-bits wide. But
//! there's no `U32x2` type, because that'd only be 64-bits wide.
//!
//!
//! # Backends
//! VectorEyes chooses what backend to execute vector operations with at compile-time.
//!
//! ## AVX2
//! x86-64 CPUs that support the `AVX`, `AVX2`, `SSE4.1`, `AES`, `SSE4.2`, and
//! `PCLMULQDQ` features will use the `AVX2` backend.
//!
//! ## Neon
//! This is available on aarch64/arm64 machines with `neon` and `aes` features.
//!
//! ## Scalar
//! This is a fallback implementation that works on all CPUs. It's not
//! particularly performant.
//!
//! # Cargo Configuration
//! If using VectorEyes from the `swanky` repo, all this configuration has already been done for
//! you!
//! ## Native CPU Setup
//! Compile on the machine that you'll be running your code on, and add the
//! following to your `.cargo/config` file:
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! rustdocflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! ```
//! ## Specific CPU Selection
//! If you want to compile for some specific CPU, add the following to your
//! `.cargo/config` file:
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! rustdocflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! ```
//! ## Maximal Compatibility
//! If you do not put any of the above in your `.cargo/config` file,
//! `vectoreyes` will always use its `scalar` backend, which does not use vector
//! instructions.
//!
//! # Limitations
//! VectorEyes was designed around the AVX2 backend. For example, shuffle operations tend to be
//! constrained to 128-bit lanes because that's how the Intel intrinsics are constrained. As a
//! result, while code that uses VectorEyes might be optimal for an Intel platform, it might not be
//! optimal for an ARM platform with different intrinsics. (This is a limitation, generally, with
//! cross-platform SIMD libraries like VectorEyes.)
//!
//! In addition, many SIMD intrinsics are currently not wrapped in VectorEyes.

use std::ops::*;

/// What backend will be used when targeting the current CPU?
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VectorBackend {
    /// The fallback scalar backend (doesn't use vector instructions).
    Scalar,
    /// A vector backend targeting [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Advanced_Vector_Extensions_2).
    Avx2,
    /// A vector backend targeting [ARM Neon](https://developer.arm.com/Architectures/Neon).
    Neon,
}

/// The vector backend that this process is using.
pub const VECTOR_BACKEND: VectorBackend = current_vector_backend();

/// Panic if the current binary uses features unsupported by the current CPU.
///
/// `vectoreyes` uses compile-time flags to select which backend to use and which CPU features to
/// require. If this backend is used on an unsupported CPU, it will result in an "Illegal
/// instruction" error (technically, _all_ Rust code--not even just `vectoreyes` code--may result in
/// undefined behavior if run on a CPU that doesn't support the compile-time selected feature
/// flags).
///
/// It would be advisable to call this in the `main()` function of executables to try to catch
/// these errors early.
pub fn assert_cpu_features() {
    vector_backend_check_cpu()
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
/// # Representation
/// This type should have the same size as `[T; Self::Lanes]`, though it may have increased
/// alignment requirements.
///
/// # Effects of signedness on shift operations
/// When `Scalar` is _signed_, shift operations are signed shifts. When `Scalar` is _unsigned_,
/// shift operations are unsigned shifts.
///
/// ## Example
/// A signed shift right will add the sign bit
/// ```
/// # use vectoreyes::*;
/// assert_eq!(
///     U64x2::from([0xffffffffffffffff, 0x2]) >> 1,
///     U64x2::from([0x7fffffffffffffff, 0x1]),
/// );
/// assert_eq!(
///     // Because the sign bit of 0xffffffffffffffff is 1, shifting right will cause a 1 to be
///     // inserted which, in this case, results in the same 0xffffffffffffffff value.
///     U64x2::from(I64x2::from(U64x2::from([0xffffffffffffffff, 0x2])) >> 1),
///     U64x2::from([0xffffffffffffffff, 0x1]),
/// );
/// ```
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
    + Add<Output = Self>
    + SubAssign
    + Sub<Output = Self>
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
    + AsRef<[Self::Scalar]>
    + AsMut<[Self::Scalar]>
{
    /// The number of elements of this vector.
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

    /// A vector where every element is zero.
    const ZERO: Self;
    /// Is `self == Self::ZERO`?
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert!(U32x4::from([0, 0, 0, 0]).is_zero());
    /// assert!(!U32x4::from([1, 0, 0, 0]).is_zero());
    /// ```
    fn is_zero(&self) -> bool;

    /// Create a new vector by setting element 0 to `value`, and the rest of the elements to `0`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(U32x4::from([64, 0, 0, 0]), U32x4::set_lo(64));
    /// ````
    fn set_lo(value: Self::Scalar) -> Self;

    /// Create a new vector by setting every element to `value`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(U32x4::from([64, 64, 64, 64]), U32x4::broadcast(64));
    /// ````
    fn broadcast(value: Self::Scalar) -> Self;

    /// A vector of `[Self::Scalar; 128 / (8 * std::mem::size_of::<Self::Scalar>())]`
    type BroadcastLoInput: SimdBase<Scalar = Self::Scalar>;
    /// Create a vector by setting every element to element 0 of `of`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(U32x4::from([1, 1, 1, 1]), U32x4::broadcast_lo(U32x4::from([1, 2, 3, 4])));
    /// ````
    fn broadcast_lo(of: Self::BroadcastLoInput) -> Self;

    /// Get the `I`-th element of this vector.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// let v = U32x4::from([1, 2, 3, 4]);
    /// assert_eq!(v.extract::<0>(), 1);
    /// assert_eq!(v.extract::<1>(), 2);
    /// assert_eq!(v.extract::<2>(), 3);
    /// assert_eq!(v.extract::<3>(), 4);
    /// ````
    fn extract<const I: usize>(&self) -> Self::Scalar;

    /// Convert the vector to an array.
    #[inline(always)]
    fn as_array(&self) -> Self::Array {
        (*self).into()
    }

    /// Shift each element left by `BITS`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(U32x4::from([1, 2, 3, 4]).shift_left::<1>(), U32x4::from([2, 4, 6, 8]));
    /// ````
    fn shift_left<const BITS: usize>(&self) -> Self;
    /// Shift each element right by `BITS`.
    /// # Effects of Signedness
    /// When `T` is _signed_, this will shift in sign bits, as opposed to zeroes.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(U32x4::from([1, 2, 3, 4]).shift_right::<1>(), U32x4::from([0, 1, 1, 2]));
    /// assert_eq!(I32x4::from([-1, -2, -3, -4]).shift_right::<1>(), I32x4::from([-1, -1, -2, -2]));
    /// ````
    fn shift_right<const BITS: usize>(&self) -> Self;

    /// Compute `self & (! other)`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x2::from([0b11, 0b00]).and_not(U64x2::from([0b10, 0b10])),
    ///     U64x2::from([0b01, 0b00]),
    /// );
    /// ````
    fn and_not(&self, other: Self) -> Self;

    /// Create a vector where each element is all 1's if the elements are equal, and all 0's otherwise.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x2::from([1, 2]).cmp_eq(U64x2::from([1, 3])),
    ///     U64x2::from([0xffffffffffffffff, 0]),
    /// );
    /// ````
    fn cmp_eq(&self, other: Self) -> Self;
    /// Create a vector where each element is all 1's if the element of `self` is greater than the
    /// corresponding element of `other`, and all 0's otherwise.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x2::from([1, 28]).cmp_gt(U64x2::from([1, 3])),
    ///     U64x2::from([0, 0xffffffffffffffff]),
    /// );
    /// ````
    fn cmp_gt(&self, other: Self) -> Self;

    /// Interleave the elements of the low half of `self` and `other`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x4::from([101, 102, 103, 104]).unpack_lo(U32x4::from([201, 202, 203, 204])),
    ///     U32x4::from([101, 201, 102, 202]),
    /// );
    /// ````
    fn unpack_lo(&self, other: Self) -> Self;
    /// Interleave the elements of the high half of `self` and `other`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x4::from([101, 102, 103, 104]).unpack_hi(U32x4::from([201, 202, 203, 204])),
    ///     U32x4::from([103, 203, 104, 204]),
    /// );
    /// ````
    fn unpack_hi(&self, other: Self) -> Self;

    /// Make a vector consisting of the maximum elements of `self` and other.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x4::from([1, 2, 3, 4]).max(U32x4::from([0, 9, 0, 0])),
    ///     U32x4::from([1, 9, 3, 4]),
    /// );
    /// ````
    fn max(&self, other: Self) -> Self;
    /// Make a vector consisting of the minimum elements of `self` and other.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x4::from([1, 2, 3, 4]).min(U32x4::from([0, 9, 0, 0])),
    ///     U32x4::from([0, 2, 0, 0]),
    /// );
    /// ````
    fn min(&self, other: Self) -> Self;
}

/// A vector supporting the gather operation (indexing into an array using indices from a vector).
pub trait SimdBaseGatherable<IV: SimdBase>: SimdBase {
    /// Construct a vector by accessing values at `base + indices[i]`.
    ///
    /// # Safety
    /// This operation is safe if `std::ptr::read(base.add(indices[i]))` is safe for all `i`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// let arr: Vec<i32> = (0..=1024).map(|x| x + 1).collect();
    /// let out = unsafe {
    ///     // SAFETY: All the indices are within bounds.
    ///     I32x4::gather(arr.as_ptr(), U64x4::from([32, 647, 827, 920]))
    /// };
    /// assert_eq!(out, I32x4::from([33, 648, 828, 921]));
    /// ```
    unsafe fn gather(base: *const Self::Scalar, indices: IV) -> Self;
    /// Construct a vector by accessing values at `base + indices[i]`, if the mask's MSB is set.
    /// Else return `src[i]`.
    ///
    /// # Safety
    /// This operation is safe if `std::ptr::read(base.add(indices[i]))` is safe for all `i`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// let arr: Vec<i32> = (0..=1024).map(|x| x + 1).collect();
    /// let out = unsafe {
    ///     // SAFETY: All the indices are within bounds.
    ///     I32x4::gather_masked(
    ///         arr.as_ptr(),
    ///         U64x4::from([32, 647, 827, 920]),
    ///         I32x4::from([-1, -1, 0, 0]),
    ///         I32x4::from([1, 2, 3, 4]),
    ///     )
    /// };
    /// assert_eq!(out, I32x4::from([33, 648, 3, 4]));
    /// ```
    unsafe fn gather_masked(base: *const Self::Scalar, indices: IV, mask: Self, src: Self) -> Self;
}

/// A vector containing 4 lanes.
pub trait SimdBase4x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x4::from([11, 12, 13, 14])
    ///         .blend::<true, true, true, false>(U64x4::from([21, 22, 23, 24])),
    ///     U64x4::from([11, 22, 23, 24]),
    /// );
    /// ````
    fn blend<const B3: bool, const B2: bool, const B1: bool, const B0: bool>(
        &self,
        if_true: Self,
    ) -> Self;
}

/// A vector containing 8 lanes.
pub trait SimdBase8x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x8::from([11, 12, 13, 14, 15, 16, 17, 18])
    ///         .blend::<true, true, true, false, false, true, true, false>(
    ///             U32x8::from([21, 22, 23, 24, 25, 26, 27, 28])),
    ///     U32x8::from([11, 22, 23, 14, 15, 26, 27, 28]),
    /// );
    /// ````
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

/// A vector supporting saturating arithmetic on each entry.
///
/// Saturating operations clamp their outputs to the scalar's maximum or minimum value on
/// overflow/underflow.
pub trait SimdSaturatingArithmetic: SimdBase {
    /// Pairwise add vectors. On overflow, the entry's value goes to the maximum scalar value.
    fn saturating_add(&self, other: Self) -> Self;
    /// Pairwise add vectors. On overflow, the entry's value goes to the minimum scalar value.
    fn saturating_sub(&self, other: Self) -> Self;
}

/// A vector containing 8-bit values.
pub trait SimdBase8: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u8, Signed = i8>,
{
    /// Split the vector into groups of 16 bytes. Within each group, shift the _entire_ bytes left
    /// by `AMOUNT`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U8x16::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).shift_bytes_left::<1>(),
    ///     U8x16::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
    /// );
    /// ```
    fn shift_bytes_left<const AMOUNT: usize>(&self) -> Self;
    /// Split the vector into groups of 16 bytes. Within each group, shift the _entire_ bytes right
    /// by `AMOUNT`.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U8x16::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).shift_bytes_right::<1>(),
    ///     U8x16::from([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0]),
    /// );
    /// ```
    fn shift_bytes_right<const AMOUNT: usize>(&self) -> Self;
    /// Get the sign/most significant bits of the elements of the vector.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     (U8x16::from([0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1]) << 7).most_significant_bits(),
    ///     0b1111001001010000,
    /// );
    /// ```
    fn most_significant_bits(&self) -> u32;
}

/// A vector containing 16-bit values.
pub trait SimdBase16: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u16, Signed = i16>,
{
    /// Shuffle within the lower 64-bits of each 128-bit subvector.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U16x16::from([
    ///         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ///     ]).shuffle_lo::<0, 1, 1, 3>(),
    ///     U16x16::from([
    ///         3, 1, 1, 0, 4, 5, 6, 7, 11, 9, 9, 8, 12, 13, 14, 15
    ///     ]),
    /// );
    /// ```
    fn shuffle_lo<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
    /// Shuffle within the upper 64-bits of each 128-bit subvector.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U16x16::from([
    ///         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ///     ]).shuffle_hi::<0, 1, 1, 3>(),
    ///     U16x16::from([
    ///         0, 1, 2, 3, 7, 5, 5, 4, 8, 9, 10, 11, 15, 13, 13, 12
    ///     ]),
    /// );
    /// ```
    fn shuffle_hi<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
}

/// A vector containing 32-bit values.
pub trait SimdBase32: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u32, Signed = i32>,
{
    /// Shuffle within 128-bit subvector.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U32x8::from([
    ///         0, 1, 2, 3, 4, 5, 6, 7
    ///     ]).shuffle::<0, 1, 1, 3>(),
    ///     U32x8::from([
    ///         3, 1, 1, 0, 7, 5, 5, 4
    ///     ]),
    /// );
    /// ```
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

/// A vector containing 64-bit values.
pub trait SimdBase64: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Zero out the upper-32 bits of each word, and then perform pairwise multiplication.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x4::from([6, 7, 8, 9]).mul_lo(U64x4::from([1, 2, 3, 4])),
    ///     U64x4::from([6, 14, 24, 36]),
    /// );
    /// assert_eq!(
    ///     U64x4::from([6, 7, 8, 9]).mul_lo(
    ///         U64x4::from([1, 2, 3, 4]) | U64x4::broadcast(u64::MAX << 32)
    ///     ),
    ///     U64x4::from([6, 14, 24, 36]),
    /// );
    /// ```
    fn mul_lo(&self, other: Self) -> Self;
}

/// A vector containing 4 64-bit values.
pub trait SimdBase4x64: SimdBase64 + SimdBase4x
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Shuffle the 64-bit values.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x4::from([0, 1, 2, 3]).shuffle::<0, 1, 1, 3>(),
    ///     U64x4::from([3, 1, 1, 0]),
    /// );
    /// ```
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

// TODO: deprecate the uses of from() everywhere and use traits/functions that make it obvious which
// casts are free and which aren't.

/// Lossily cast a vector by {zero,sign}-extending its values.
pub trait ExtendingCast<T: SimdBase>: SimdBase {
    /// Cast from one vector to another by sign or zero extending the values from the source until it
    /// fills the destination.
    ///
    /// The lowest-index values in `t` are kept. Any values which don't fit are discarded.
    ///
    /// # Example
    /// ```
    /// # use vectoreyes::*;
    /// assert_eq!(
    ///     U64x2::extending_cast_from(U32x4::from([1, 2, 3, 4])),
    ///     U64x2::from([1, 2]),
    /// );
    /// ```
    fn extending_cast_from(t: T) -> Self;
}

/// A [`Scalar`] type which has a vector type of length `N`.
///
/// See [`Simd`] for how this trait is used.
pub trait HasVector<const N: usize>: Scalar {
    /// The vector of `[Self; N]`.
    type Vector: SimdBase<Scalar = Self>;
}

/// An alternative way of naming SIMD types.
///
/// This allows for functions to be written which are generic in the type or length of a vector.
///
/// # Example
/// ```
/// # use vectoreyes::*;
/// type MyVector = Simd<u8, 16>; // The same as U8x16.
///
/// fn my_length_generic_code<const N: usize>(x: Simd<u32, N>, y: Simd<u32, N>) -> Simd<u32, N>
///     where u32: HasVector<N>
/// {
///     x + x + y
/// }
/// ```
pub type Simd<T, const N: usize> = <T as HasVector<N>>::Vector;

/// An AES block cipher, suitable for encryption.
///
/// This cipher can be used for encryption. Decryption operations are handled in the subtrait
/// [`AesBlockCipherDecrypt`].
pub trait AesBlockCipher: 'static + Clone + Sync + Send {
    /// The type of the AES key.
    type Key: 'static + Clone + Sync + Send;

    /// Running `encrypt_many` with this many blocks will typically result in good
    /// performance.
    const BLOCK_COUNT_HINT: usize;

    /// Run the AES key schedule operation with a given key.
    fn new_with_key(key: Self::Key) -> Self;

    /// Encrypt a single 128-bit AES block.
    #[inline(always)]
    fn encrypt(&self, block: U8x16) -> U8x16 {
        self.encrypt_many([block])[0]
    }
    /// Encrypt an array of `N` 128-bit AES blocks using ECB mode.
    fn encrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

/// An AES block cipher, suitable for encryption and decryption.
pub trait AesBlockCipherDecrypt: AesBlockCipher {
    /// Decrypt a single 128-bit AES block.
    #[inline(always)]
    fn decrypt(&self, block: U8x16) -> U8x16 {
        self.decrypt_many([block])[0]
    }
    /// Decrypt an array of `N` 128-bit AES blocks using ECB mode.
    fn decrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

pub mod array_utils;
pub(crate) mod utils;

// We want to allow `which_lane * 0 + 0` expressions.
// These also allow for simpler generated code. For example, sometimes we have code which looks
// like:
//    let x: {{ty}};
//    x as u8
// When {{ty}} _is_ u8, this cast isn't neccessary. But it's simpler to always insert it in the
// generated code.
#[allow(
    clippy::identity_op,
    clippy::erasing_op,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]
// intel intrinsics have many arguments
#[allow(clippy::too_many_arguments)]
// our compressed code doesn't have newlines
#[allow(clippy::suspicious_else_formatting)]
// You can't put inline(always) without a closure
#[allow(clippy::redundant_closure)]
// These two lints let us have extra parentheses in the generated source (which makes generation
// easier).
#[allow(unused_parens)]
#[allow(clippy::needless_borrow)]
// </the two lints>
mod generated;
pub use generated::implementation::*;
