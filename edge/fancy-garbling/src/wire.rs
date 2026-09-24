//! Wirelabels for use in garbled circuits.
//!
//! This module contains a [`WireLabel`] trait, alongside various instantiations
//! of this trait. The [`WireLabel`] trait is the core underlying primitive used
//! in garbled circuits, and represents an encoding of the value on any given
//! wire of the circuit.

use fancy_traits::HasModulus;
use rand::CryptoRng;
use subtle::ConditionallySelectable;
use swanky_cr_hash::TweakableCircularCorrelationRobustHash;
use vectoreyes::{
    U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

mod mod2;
pub use mod2::WireMod2;

/// Hash a batch of wires, using the same tweak for each wire.
pub fn hash_wires<const Q: usize, W: WireLabel>(wires: [&W; Q], tweak: u128) -> [U8x16; Q]
where
    ArrayUnrolledOps: UnrollableArraySize<Q>,
{
    let batch = wires.array_map(|x| x.to_repr());
    TweakableCircularCorrelationRobustHash::fixed_key().hash_many(batch, tweak)
}

/// The [`BinaryWireLabel`] provides the subroutines to implement AND gates
/// for the garbler and evaluator in [`fancy_traits::FancyBinary`].
pub trait BinaryWireLabel: WireLabel + ConditionallySelectable {
    /// Garbles an 'and' gate given two input wires and the delta.
    ///
    /// Outputs a tuple consisting of the two gates (that should be transfered to the evaluator)
    /// and the next wirelabel for the garbler.
    fn garble_and_gate(gate_num: usize, A: &Self, B: &Self, delta: &Self) -> (U8x16, U8x16, Self);

    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    fn evaluate_and_gate(gate_num: usize, A: &Self, B: &Self, gate0: &U8x16, gate1: &U8x16)
    -> Self;
}

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
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn hash_to_mod(hash: U8x16, q: u16) -> Self;

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
