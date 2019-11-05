// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{SyncChannel, TrackChannel};
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

/// A SyncChannel which uses UnixStreams.
pub type UnixChannel = SyncChannel<BufReader<UnixStream>, BufWriter<UnixStream>>;

/// A TrackChannel which uses UnixStreams.
pub type TrackUnixChannel = TrackChannel<BufReader<UnixStream>, BufWriter<UnixStream>>;

/// Convenience function to create a pair of UnixChannels for local tests in `swanky`.
pub fn unix_channel_pair() -> (UnixChannel, UnixChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = SyncChannel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
    let receiver = SyncChannel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    (sender, receiver)
}

/// Convenience function to create a pair of TrackUnixChannels for local tests in `swanky`.
pub fn track_unix_channel_pair() -> (TrackUnixChannel, TrackUnixChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = TrackChannel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
    let receiver = TrackChannel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    (sender, receiver)
}
