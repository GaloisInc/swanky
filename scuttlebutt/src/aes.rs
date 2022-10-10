//! Implementations of AES-128 and AES-256, encryption only, using Intel's
//! AES-NI instructions.
//!
//! Most of this implementation is borrowed and simplified from the `aesni`
//! crate.

pub mod aes128;
pub mod aes256;
