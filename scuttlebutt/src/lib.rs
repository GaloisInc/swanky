// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

//!

mod aes;
mod block;
mod block512;
#[cfg(feature = "hash_channel")]
pub mod bloomfilter;
/// Module for encapsulating communication channels for `swanky`.
pub mod channel;
#[cfg(feature = "cointoss")]
pub mod cointoss;
#[cfg(feature = "hash_channel")]
pub mod commitment;
#[cfg(feature = "hash_aes")]
mod hash_aes;
#[cfg(feature = "rand_aes")]
mod rand_aes;
pub mod utils;

pub use crate::{
    aes::{aes128::Aes128, aes256::Aes256},
    block::Block,
    block512::Block512,
    channel::{AbstractChannel, Channel},
};

#[cfg(feature = "sym_channel")]
pub use crate::channel::SymChannel;

#[cfg(feature = "sync_channel")]
pub use crate::channel::SyncChannel;

#[cfg(feature = "track_channel")]
pub use crate::channel::TrackChannel;

#[cfg(feature = "hash_channel")]
pub use crate::channel::HashChannel;

#[cfg(feature = "hash_aes")]
pub use crate::hash_aes::AesHash;

#[cfg(feature = "rand_aes")]
pub use crate::rand_aes::AesRng;

#[cfg(all(unix, feature = "unix_channel"))]
pub use crate::channel::{
    track_unix_channel_pair, unix_channel_pair, TrackUnixChannel, UnixChannel,
};

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious: SemiHonest {}
