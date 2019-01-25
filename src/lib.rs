#![feature(non_ascii_idents)]
#![feature(test)]
#![feature(reverse_bits)]

extern crate aesni as aes;
#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate itertools;

pub mod ot;
