#![feature(non_ascii_idents)]
#![feature(test)]
#![feature(reverse_bits)]

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate itertools;

mod aes;
mod ot;
mod rand_aes;
pub use crate::ot::*;
