#![deny(clippy::all)]
#![allow(
    clippy::cast_lossless,
    clippy::new_without_default,
    clippy::type_complexity,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]
#![allow(non_snake_case)]

pub mod circuit;
pub mod dummy;
pub mod error;
mod fancy;
mod garble;
pub mod informer;
mod parser;
pub mod util;
mod wire;

pub use crate::error::FancyError;
pub use crate::fancy::*;
pub use crate::garble::*;
pub use crate::wire::*;
