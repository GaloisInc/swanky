// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

//!

#[macro_use]
extern crate impl_ops;

mod aes;
mod block;
mod block512;
pub mod bloomfilter;
/// Module for encapsulating communication channels for `swanky`.
pub mod channel;
#[cfg(feature = "cointoss")]
pub mod cointoss;
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
    channel::{AbstractChannel, Channel, HashChannel, SymChannel, SyncChannel, TrackChannel},
};

#[cfg(feature = "hash_aes")]
pub use crate::hash_aes::AesHash;

#[cfg(feature = "rand_aes")]
pub use crate::rand_aes::AesRng;

#[cfg(unix)]
pub use crate::channel::{
    track_unix_channel_pair, unix_channel_pair, TrackUnixChannel, UnixChannel,
};

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious: SemiHonest {}
