//! Helper types to make using the
//! [`generic-array`](https://docs.rs/generic-array/latest/generic_array/) easier.
//!
//! We use the `generic-array` crate, so that we can support situations like:
//! ```text
//! trait Foo {
//!     const N: usize;
//! }
//! struct Blarg<F: Foo> {
//!     contents: [u8; F::N],
//! }
//! ```
//!
//! While _some_ of the original use cases for `generic-array` can be accomplished since the
//! stabilization of `min_const_generics`, other use cases (like the above) remain unstable (as of
//! Rust 1.65).
//!
//! The `generic_array` crate uses a _type_, instead of a constant, to represent the length of the
//! array. `generic_array` exposes the [`ArrayLength`] trait to denote a type which represents the
//! length of an array. Due to internal reasons, `ArrayLength` is parametrized on the type of an
//! _element_ of the array. For example, we would write code like:
//! ```
//! trait MyBlockCipher {
//!     type BlockSize: generic_array::ArrayLength<u8>;
//! }
//! fn foo<C: MyBlockCipher>(x: generic_array::GenericArray<u8, C::BlockSize>) {
//!     let _ = x; // do something!
//! }
//! ```
//! This code lets us use `BlockSize` _only_ to create arrays of `u8`s. If you want to create an
//! array of any other size, you're out of luck.
//!
//! In Rust 1.65, Generic Associated Types were stabilized. This provides a solution for us to work
//! around this issue, and let us specify array lengths which can be used with any element type.
//!
//! Use this module as follows:
//! ```
//! # use swanky_generic_array::{AnyArrayLength, Arr};
//! trait MyBlockCipher {
//!     type BlockSize: AnyArrayLength;
//! }
//! fn foo<C: MyBlockCipher>(x: Arr<u8, C::BlockSize>) {
//!     let _ = x; // do something!
//! }
//! ```
//! Because we've used `AnyArrayLength`, we can instantiate an array of length `BlockSize` with
//! any type that we want! (And we couldn't do that with the "normal" `GenericArray` solution.)
//! ```
//! # use swanky_generic_array::{AnyArrayLength, Arr};
//! # trait MyBlockCipher {
//! #     type BlockSize: AnyArrayLength;
//! # }
//! fn blarg<C: MyBlockCipher>(x: Arr<(i32, String), C::BlockSize>) {
//!     let _ = x; // do something!
//! }
//! ```

use generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    ArrayLength, GenericArray,
};

/// A marker type denoting that `Self` corresponds to an `ArrayLength` over any type
pub trait AnyArrayLength {
    /// The underlying `ArrayLength`, which should always equal `Self`
    type OutputArrayLength<T>: ArrayLength<T>;
}
impl AnyArrayLength for UTerm {
    type OutputArrayLength<T> = Self;
}
impl<N: AnyArrayLength> AnyArrayLength for UInt<N, B0> {
    type OutputArrayLength<T> = UInt<<N as AnyArrayLength>::OutputArrayLength<T>, B0>;
}
impl<N: AnyArrayLength> AnyArrayLength for UInt<N, B1> {
    type OutputArrayLength<T> = UInt<<N as AnyArrayLength>::OutputArrayLength<T>, B1>;
}

/// A [`GenericArray`] of length `N` containing type `T`
///
/// Instead of `N` being constrainted by [`ArrayLength`] (as in `GenericArray`), it's constrainted
/// by [`AnyArrayLength`].
///
/// This type alias resolves to a `GenericArray`, and it can be used with any existing
/// `GenericArray` code.
pub type Arr<T, N> = GenericArray<T, <N as AnyArrayLength>::OutputArrayLength<T>>;
