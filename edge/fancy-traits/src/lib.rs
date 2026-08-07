//! Traits for representing circuit computations.
//!
//! The core trait of this module is [`Fancy`], which represents the basic set
//! of operations possible in a circuit. There are also extension traits that
//! further extend the core [`Fancy`] trait to provide additional capabilities.
#![deny(missing_docs)]

use swanky_channel::Channel;
use swanky_error::Result;

mod circuit;
pub use circuit::{Circuit, CircuitInputMapper, CircuitOutputMapper};
mod zk;
pub use zk::FancyZeroKnowledge;

/// An object that has a modulus.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// The `Fancy` trait is the core trait for writing circuits.
///
/// The trait contains an associated type, [`Fancy::Item`], which defines the
/// underlying wire representation, alongside a [`Fancy::constant`] method for
/// creating constant (public) wires.
///
/// This trait can be further extended to support binary, arithmetic, and/or
/// projections by using the [`FancyBinary`], [`FancyArithmetic`], or
/// [`FancyProj`] extension traits, respectively. The [`FancyEncode`] trait
/// allows for encoding values into wires, and the [`FancyOutput`] trait allows
/// for converting wires into their underlying plaintext representation.
pub trait Fancy {
    /// The underlying wire representation of this [`Fancy`] object.
    type Item: Clone + HasModulus + core::fmt::Debug + core::default::Default;
}

/// Extension trait for [`Fancy`] that provides the ability to encode public constants.
pub trait FancyConstant: Fancy {
    /// Encode a constant value `x % q`.
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> Result<Self::Item>;
}

/// Extension trait for [`Fancy`] that provides the ability to encode public
/// constants, optimized for the binary setting.
pub trait FancyBinaryConstant: Fancy {
    /// Encode a binary constant value.
    fn constant(&mut self, x: bool) -> Self::Item;
}

/// Extension trait for [`Fancy`] that provides encoding and receiving operations.
pub trait FancyEncode: Fancy {
    /// Encode many wires for known values.
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<Self::Item>>;

    /// Receive many wires for unknown values.
    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Self::Item>>;

    /// Encode a wire for a known value.
    fn encode(&mut self, value: u16, modulus: u16, channel: &mut Channel) -> Result<Self::Item> {
        let xs = self.encode_many(&[value], &[modulus], channel)?;
        Ok(xs[0].clone())
    }

    /// Receive a wire for an unknown value.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> Result<Self::Item> {
        let xs = self.receive_many(&[modulus], channel)?;
        Ok(xs[0].clone())
    }
}

/// Extension trait for [`Fancy`] that provides output operations.
pub trait FancyOutput: Fancy {
    /// Output the value associated with wire `x`.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<u16>>;

    /// Output the values associated with a slice of wires.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn outputs(&mut self, xs: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<u16>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.output(x, channel)?);
        }
        Ok(zs.into_iter().collect())
    }
}

/// Extension trait for [`Fancy`] that provides binary operations.
pub trait FancyBinary: Fancy {
    /// Binary XOR.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Binary AND.
    fn and(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item>;

    /// Binary negation.
    fn negate(&mut self, x: &Self::Item) -> Self::Item;

    /// Binary OR.
    fn or(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item> {
        let notx = self.negate(x);
        let noty = self.negate(y);
        let z = self.and(&notx, &noty, channel)?;
        Ok(self.negate(&z))
    }
}

/// Extension trait for [`Fancy`] that provides arithmetic operations.
pub trait FancyArithmetic: Fancy {
    /// Add `x` and `y`.
    ///
    /// # Panics
    /// This panics if `x` and `y` do not have equal moduli.
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Subtract `x` and `y`.
    ///
    /// # Panics
    /// This panics if `x` and `y` do not have equal moduli.
    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Multiply `x` with the constant `c`.
    fn cmul(&mut self, x: &Self::Item, c: u16) -> Self::Item;

    /// Multiply `x` and `y`.
    fn mul(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item>;
}

/// Extension trait for [`Fancy`] that provides a projection gate, alongside
/// methods that utilize projection gates.
///
/// # Security Warning
/// In its current form, using projection gates in arithmetic garbling is
/// **insecure**.
pub trait FancyProj: Fancy {
    /// Project `x` according to the truth table `tt`. Resulting wire has
    /// modulus `q`.
    ///
    /// Optional `tt` is useful for hiding the gate from the evaluator.
    ///
    /// # Panics
    /// This may panic in certain implementations if `tt` is `None` when it
    /// should be `Some`. In addition, it may panic if `tt` is improperly
    /// formed: either the length of `tt` is smaller than `x`s modulus, or the
    /// values in `tt` are larger than `q`.
    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> Result<Self::Item>;
}

/// Utility macro for asserting that a wire is binary (i.e., has modulus two).
#[macro_export]
macro_rules! is_binary {
    ($x:ident) => {
        assert_eq!($x.modulus(), 2);
    };
}
