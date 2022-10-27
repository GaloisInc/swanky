#![allow(clippy::many_single_char_names)]
#![deny(missing_docs)]
#![cfg_attr(feature = "nightly", feature(test))]
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
pub mod field;
mod hash_aes;
mod rand_aes;
pub mod ring;
#[macro_use]
pub mod serialization;
pub mod utils;

pub(crate) mod ops;

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
