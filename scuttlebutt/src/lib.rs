#![allow(clippy::many_single_char_names)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

//! Scuttlebutt provides many utility functions for cryptographic applications.

mod aes;
mod block;
mod block512;
pub mod bloomfilter;
/// Module for encapsulating communication channels for `swanky`.
pub mod channel;
pub mod cointoss;
pub mod commitment;
mod hash_aes;
mod rand_aes;
pub use swanky_generic_array as generic_array_length;
pub use swanky_serialization as serialization;
pub mod utils;

/// A polyfill for the `swanky-field*` family of crates.
pub mod field {
    pub use swanky_field::{
        field_ops, polynomial, Degree, DegreeModulo, FiniteField, IsSubFieldOf, PrimeFiniteField,
    };
    pub use swanky_field_binary::*;
    pub use swanky_field_f61p::*;
    pub use swanky_field_ff_primes::*;
    pub use swanky_field_fft as fft;
}
/// A polyfill for the ring functionality inside of `swanky-field`.
pub mod ring {
    pub use swanky_field::{ring_ops, FiniteRing, IsSubRingOf};
}

pub use crate::{
    aes::{
        aes128::{Aes128, FIXED_KEY_AES128},
        aes256::Aes256,
    },
    block::Block,
    block512::Block512,
    channel::{AbstractChannel, Channel, HashChannel, SymChannel, SyncChannel, TrackChannel},
    hash_aes::{AesHash, AES_HASH},
    rand_aes::{vectorized::UniformIntegersUnderBound, AesRng},
};

#[cfg(unix)]
pub use crate::channel::{
    track_unix_channel_pair, unix_channel_pair, TrackUnixChannel, UnixChannel,
};

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious: SemiHonest {}
