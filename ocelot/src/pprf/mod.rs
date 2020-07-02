
//! Puncturable Pseudo-Random Function (PPRF) traits
//!
//! This module provides traits for PPRF

pub mod pprf;
#[allow(unused_imports)]
use rand::{CryptoRng, Rng};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block};
pub use bit_vec::BitVec;
//TODO: change this type to field type later
pub type Fpr = u32;
pub type Fpr2 = (Fpr, Fpr);



