//! Ocelot is an oblivious transfer (+ extension) library written in rust.
//! Currently it only implements semi-honest constructions.
//!
//! **THIS IS VERY MUCH RESEARCH CODE!** (for now)

#![feature(non_ascii_idents)]
#![feature(test)]

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate itertools;

mod aes;
mod hash_aes;
mod ot;
mod rand_aes;
mod utils;
pub use crate::ot::*;
