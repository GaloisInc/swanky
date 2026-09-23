//! `fancy-garbling` provides boolean and arithmetic garbling capabilities.
#![allow(non_snake_case)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

pub mod classic;
mod garble;
pub mod util;
mod wire;

pub use crate::garble::{Evaluator, Garbler};
pub use crate::wire::{AllWire, WireMod2, WireMod3, WireModQ};
pub use crate::wire::{ArithmeticWireLabel, BinaryWireLabel, WireLabel};
