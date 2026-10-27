//! Traits for writing and evaluating circuits.
//!
//! The core trait of this crate is [`Fancy`], which defines the circuit's wire
//! representation. In addition, there are several extension traits that extend
//! the capabilities of a [`Fancy`] object, such as to support encoding
//! constants (through the [`FancyConstant`] trait) or enabling binary operators
//! (through the [`FancyBinary`] trait).
//!
//! Circuits are defined using the [`Circuit`] trait, which is generic over some
//! [`Fancy`] object. Any [`Fancy`] object can then execute the defined
//! [`Circuit`] object, and other circuits may call [`Circuit`] implementations
//! as subcomponents.
//!
//! # Example
//! Below, we define a simple "plaintext" evaluator over `bool`s, and implement
//! [`Fancy`] and [`FancyBinary`] for this evaluator.
//! ```
//! # use fancy_traits::{Fancy, FancyBinary};
//! # use swanky_channel::Channel;
//! # use swanky_error::Result;
//! struct BooleanEvaluator;
//!
//! impl Fancy for BooleanEvaluator {
//!     type Item = bool;
//! }
//! impl FancyBinary for BooleanEvaluator {
//!     fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
//!         x ^ y
//!     }
//!     fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
//!         Ok(x & y)
//!     }
//!     fn negate(&mut self, x: &Self::Item) -> Self::Item {
//!         !x
//!     }
//! }
//! ```
//! We can then use this evaluator to a [`Circuit`] by calling
//! [`Circuit::execute`] with the backend set to `BooleanEvaluator`.
#![deny(missing_docs)]

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteField;

mod circuit;
pub use circuit::{Circuit, CircuitInputMapper, CircuitOutputMapper};
mod zk;
pub use zk::FancyZeroKnowledge;

/// The `Fancy` trait is the core trait for writing circuits.
///
/// The trait contains an associated type, [`Fancy::Item`], which defines the
/// underlying wire representation.
///
/// This trait can be further extended to support binary by using the
/// [`FancyBinary`] extension trait. The [`FancyEncode`] trait allows for
/// encoding values into wires, and the [`FancyOutput`] trait allows for
/// converting wires into their underlying plaintext representation.
pub trait Fancy {
    /// The underlying wire representation of this [`Fancy`] object.
    type Item: Clone + core::fmt::Debug + Default;
}

/// Extension trait for [`Fancy`] that provides the ability to encode public constants.
pub trait FancyConstant<FF: FiniteField>: Fancy {
    /// Encode a constant value `x`.
    fn constant(&mut self, x: FF) -> Self::Item;
}

/// Extension trait for [`Fancy`] that provides encoding and receiving operations.
pub trait FancyEncode<FF: FiniteField>: Fancy {
    /// Encode many wires for known values.
    fn encode_many(&mut self, values: &[FF], channel: &mut Channel) -> Result<Vec<Self::Item>>;

    /// Receive many wires for unknown values.
    fn receive_many(&mut self, n: usize, channel: &mut Channel) -> Result<Vec<Self::Item>>;

    /// Encode a wire for a known value.
    fn encode(&mut self, value: FF, channel: &mut Channel) -> Result<Self::Item> {
        let xs = self.encode_many(&[value], channel)?;
        Ok(xs[0].clone())
    }

    /// Receive a wire for an unknown value.
    fn receive(&mut self, channel: &mut Channel) -> Result<Self::Item> {
        let xs = self.receive_many(1, channel)?;
        Ok(xs[0].clone())
    }
}

/// Extension trait for [`Fancy`] that provides output operations.
pub trait FancyOutput<FF: FiniteField>: Fancy {
    /// Output the value associated with wire `x`.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<FF>>;

    /// Output the values associated with a slice of wires.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn outputs(&mut self, xs: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<FF>>> {
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
