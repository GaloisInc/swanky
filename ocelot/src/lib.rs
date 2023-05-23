//! `ocelot` provides oblivious transfer, oblivious PRFs and sVOLE extension.
#![cfg_attr(feature = "nightly", feature(test))]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::type_complexity)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

mod errors;
mod utils;
pub use crate::errors::Error;
pub mod oprf;
pub mod ot;
pub mod svole;
