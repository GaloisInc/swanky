use crate::AbstractChannel;
use std::{
    io::Result,
    sync::{Arc, Mutex},
};

/// A channel wrapping another channel for tracking the number of bits read/written.
pub struct TrackChannel<C>(Arc<Mutex<InternalTrackChannel<C>>>);

struct InternalTrackChannel<C> {
    channel: C,
    nbits_read: usize,
    nbits_written: usize,
}

impl<C: AbstractChannel> TrackChannel<C> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(channel: C) -> Self {
        let internal = InternalTrackChannel {
            channel,
            nbits_read: 0,
            nbits_written: 0,
        };
        Self(Arc::new(Mutex::new(internal)))
    }

    /// Clear the number of bits read/written.
    pub fn clear(&mut self) {
        let mut int = self.0.lock().unwrap();
        int.nbits_read = 0;
        int.nbits_written = 0;
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.0.lock().unwrap().nbits_written as f64 / 1000.0
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.0.lock().unwrap().nbits_read as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel.
    pub fn total_kilobits(&self) -> f64 {
        let int = self.0.lock().unwrap();
        (int.nbits_written + int.nbits_read) as f64 / 1000.0
    }

    /// Return the number of kilobytes written to the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.0.lock().unwrap().nbits_written as f64 / 8192.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.0.lock().unwrap().nbits_read as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel as kilobytes.
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_written() + self.kilobytes_read()
    }
}

impl<C: AbstractChannel> AbstractChannel for TrackChannel<C> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut int = self.0.lock().unwrap();
        int.nbits_written += bytes.len() * 8;
        int.channel.write_bytes(bytes)
    }

    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        let mut int = self.0.lock().unwrap();
        int.nbits_read += bytes.len() * 8;
        int.channel.read_bytes(&mut bytes)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.lock().unwrap().channel.flush()
    }

    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
