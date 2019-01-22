#![feature(non_ascii_idents)]
#![feature(test)]

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate itertools;
extern crate aesni as aes;

pub mod ot;
pub mod util;
