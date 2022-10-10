#![cfg_attr(feature = "nightly", feature(test))]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

//!

mod cuckoo;
mod errors;
mod psi;
pub mod utils;

pub use crate::{errors::Error, psi::*};
