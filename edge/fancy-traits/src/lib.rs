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
use swanky_field::FiniteField;
pub use zk::FancyZeroKnowledge;

/// An object that has a modulus.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

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
