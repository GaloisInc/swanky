#![deny(missing_docs)]
//! Implementation of the Naor-Pinkas oblivious transfer protocol (cf.
//! <https://dl.acm.org/citation.cfm?id=365502>).
//!
//! This implementation uses the Ristretto prime order elliptic curve
//! group from the `curve25519-dalek` library

use curve25519_dalek::RistrettoPoint;

use vectoreyes::U8x16;

/// Compute `$H(K, T)$`, where `$K$` is a Ristretto point and `$T$` is
/// a tweak value.
///
/// This implementation is used to fix the bug referenced in the
/// module-level documentation.
fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> U8x16 {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    U8x16::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).expect("The slice is exactly 16 bytes"))
}
