#![deny(clippy::all)]
#![allow(
    clippy::cast_lossless,
    clippy::new_without_default,
    clippy::new_without_default_derive,
    clippy::block_in_if_condition_stmt,
    clippy::map_entry,
    clippy::needless_range_loop
)]

#![feature(try_from, no_panic_pow)]
#![allow(non_snake_case)]

pub mod circuit;
pub mod garble;
pub mod numbers;
pub mod wire;
pub mod util;
pub mod aes;
