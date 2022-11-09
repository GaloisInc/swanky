//! `inferno` is an implementation of the non-interactive variant of the
//! [Limbo zero knowledge proof protocol](https://eprint.iacr.org/2021/215).

mod cache;
mod circuit;
mod hashers;
mod proof;
mod proof_single;
mod round;
mod secretsharing;
mod utils;

pub use proof::Proof;

#[cfg(test)]
mod tests;
