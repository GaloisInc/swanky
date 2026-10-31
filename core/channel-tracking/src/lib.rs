#![deny(missing_docs)]
//! A wrapper for (ideally unbuffered) full-duplex connections that
//! keeps track of how much communication actually occurred.
//! Being full-duplex itself, it is fully compatible with
//! `swanky-channel`'s `Channel::with` / `Channel::with_sizes`.
//!
//! The [`TrackChannel`] type behaves identically to the channel it
//! wraps, except that it keeps track of the number of bits that are
//! read and written via underlying calls to [`std::io::Read`] and
//! [`std::io::Write`] methods.
//! It is useful when debugging and writing examples of protocols to
//! display how much data is actually transmitted during their
//! execution.
//!
//! Note that since `Channel::with` and `Channel::with_sizes` take
//! ownership of the underlying channel passed to them, when using
//! the `TrackChannel` type it is most useful to pass a mutable
//! reference (which automatically implements `std::io::Read` and
//! `std::io::Write` as well) instead, so that the value is still
//! accessible when the communication has completed.

use std::io::{Read, Write};

/// A full-duplex channel wrapper that keeps track of the amount of
/// data that is read/written from/to the channel.
///
/// If using this type with `swanky-channel`, the underlying channel
/// `C` should ideally be unbuffered.
pub struct TrackChannel<C: Read + Write> {
    channel: C,
    bits_read: usize,
    bits_written: usize,
}

impl<C: Read + Write> TrackChannel<C> {
    /// Create a new [`TrackChannel`] around `channel`.
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            bits_read: 0,
            bits_written: 0,
        }
    }
}
