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
//!
//! For example:
//!
//! ```
//! use std::os::unix::net::UnixStream;
//!
//! use swanky_channel::Channel;
//! use swanky_channel_tracking::TrackChannel;
//! use swanky_error::Result;
//!
//! fn do_a_work(c: &mut Channel) -> Result<i32> {
//!     c.write(&17)?;
//!     c.read()
//! }
//!
//! fn do_b_work(c: &mut Channel) -> Result<i32> {
//!     let res = c.read()?;
//!     c.write(&71)?;
//!     Ok(res)
//! }
//!
//! fn main() {
//!     let (sender, receiver) = UnixStream::pair().unwrap();
//!     let handle = std::thread::spawn(move || {
//!         let mut sender = TrackChannel::new(sender);
//!         let a_res = Channel::with(&mut sender, |c| {
//!             do_a_work(c)
//!         }).unwrap();
//!         println!(
//!             "Sender communication (read): {:.2} Kb",
//!             sender.kilobits_read()
//!         );
//!         println!(
//!             "Sender communication (write): {:.2} Kb",
//!             sender.kilobits_written()
//!         );
//!     });
//!     let mut receiver = TrackChannel::new(receiver);
//!     let b_res = Channel::with(&mut receiver, |c| {
//!         do_b_work(c)
//!     }).unwrap();
//!     handle.join().unwrap();
//!     println!(
//!         "Receiver communication (read): {:.2} Kb",
//!         receiver.kilobits_read()
//!     );
//!     println!(
//!         "Receiver communication (write): {:.2} Kb",
//!         receiver.kilobits_written()
//!     );
//! }
//! ```

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

    /// Clear the tracking data for this [`TrackChannel`].
    ///
    /// This allows the channel to be reused for statistics-gathering
    /// without having to create a brand new underlying channel.
    pub fn clear(&mut self) {
        self.bits_read = 0;
        self.bits_written = 0;
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.bits_read as f64 / 1000.0
    }

    /// Return the number of kilobits written from the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.bits_written as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel (as
    /// kilobits).
    pub fn total_kilobits(&self) -> f64 {
        (self.bits_read + self.bits_written) as f64 / 1000.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.bits_read as f64 / 8192.0
    }

    /// Return the number of kilobytes written from the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.bits_written as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel (as
    /// kilobytes).
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_read() + self.kilobytes_written()
    }
}

impl<C: Read + Write> Read for TrackChannel<C> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.channel.read(buf)?;
        self.bits_read += bytes_read * 8;
        Ok(bytes_read)
    }
}

impl<C: Read + Write> Write for TrackChannel<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes_written = self.channel.write(buf)?;
        self.bits_written += bytes_written * 8;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.channel.flush()
    }
}
