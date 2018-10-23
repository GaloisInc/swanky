#![deny(clippy::all)]
#![allow(
    clippy::cast_lossless,
    clippy::new_without_default,
    clippy::new_without_default_derive,
    clippy::block_in_if_condition_stmt,
    clippy::map_entry,
    clippy::needless_range_loop
)]

#![feature(reverse_bits)]
#![allow(non_snake_case)]

extern crate gmp;
extern crate libc;
extern crate rand as extern_rand;
extern crate base_conversion; // local dependency

pub mod circuit;
pub mod garble;
pub mod high_level;
pub mod numbers;
pub mod rand;
pub mod wire;
