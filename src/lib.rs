//! `ocelot` is an oblivious transfer (+ extension) library written in rust.
//! Currently it only implements semi-honest constructions.
//!
//! `ocelot` attempts to use all the latest-and-greatest optimizations, including:
//! * Fixed-key AES wherever possible (cf. <https://eprint.iacr.org/2019/074>)
//! * An assembly implementation of matrix transposition from the EMP toolkit's OT implementation (cf. <https://github.com/emp-toolkit/emp-ot>)
//!
//! Even with these optimizations, we are currently far from the performance of
//! other libraries, such as the EMP toolkit. Hopefully someday we'll get there!
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
