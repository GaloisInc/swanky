//! Implementation of a very simple (flat) arithmetic circuit representation.
//!
//! Circuits are encoded as a vector of gate operations. Each operation encodes
//! its input wires as indices into the vector, with the output wire implicit.

#![deny(missing_docs)]

pub mod builder;
mod circuit;
pub mod circuitgen;
pub mod reader;
#[cfg(feature = "serde")]
mod serialization;

pub use crate::circuit::{Circuit, Op};
