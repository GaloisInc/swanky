//! This crate contains the core types used for communication in Swanky.
//!
//! [`Channel`] is the type that should be used for (most) network communications in Swanky. If you
//! need to perform network communication for testing, see the [`local`] module.

#![deny(missing_docs)]

use std::io::{Read, Write};

use eyre::Context;
use generic_array::GenericArray;
use swanky_serialization::CanonicalSerialize;

pub mod local;

/// Rust doesn't support `(dyn Read + Write)`, so we make this trait, so we can write `dyn
/// ReadWrite`, instead.
trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

/// A tag denoting that an error was caused by a network error.
///
/// # Checking for Network Error
///
/// [`eyre::Error`]s can be queried to see if they're due to a [`NetworkError`]
///
/// ```rust
/// use swanky_channel::NetworkError;
///
/// let e = eyre::eyre!("My Error");
/// let e = e.wrap_err(NetworkError);
/// let e = e.wrap_err("Some other message");
/// assert!(e.is::<NetworkError>());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkError;
impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NetworkError {}

/// How big should the read and write buffers be for a [`Channel`]?
pub struct BufferSizes {
    /// Size (in bytes) of the read buffer
    pub read: usize,
    /// Size (in bytes) of the write buffer
    pub write: usize,
}
impl Default for BufferSizes {
    fn default() -> Self {
        BufferSizes {
            read: 1024 * 1024,
            write: 1024 * 16,
        }
    }
}

/// A network channel wrapper
///
/// This wrapper provides buffering and automatic flushing of the channel.
///
/// # Flushing
/// `Channel` will automatically flush the write buffer before performing a read. As a result,
/// users of the `Channel` API should almost never need to manually flush.
///
/// # Error Handling
/// On error, `Channel` is left in an unknown state. For example, if a `Channel` wraps a
/// `TcpStream`, and a `write_bytes` fails with an
/// [`ETIMEDOUT`](https://man7.org/linux/man-pages/man7/tcp.7.html#ERRORS) error, due to the
/// [Two Generals' Problem](https://en.wikipedia.org/wiki/Two_Generals%27_Problem), it's not
/// possible to know whether or not the peer received the sent data.
pub struct Channel<'a> {
    read_buffer: Vec<u8>,
    read_buffer_pos: usize,
    read_buffer_len: usize,
    write_buffer: Vec<u8>,
    inner: &'a mut dyn ReadWrite,
}

impl Channel<'_> {
    /// Construct a new `[Channel]` wrapping the full-duplex connection, `inner`.
    ///
    /// This function is equivalent to calling [`Channel::with_sizes`] with the default
    /// [`BufferSizes`]. See that function for more information.
    pub fn with<C, T, F>(inner: C, thunk: F) -> eyre::Result<T>
    where
        for<'a, 'b> F: FnOnce(&'a mut Channel<'b>) -> eyre::Result<T>,
        C: Read + Write,
    {
        Self::with_sizes(inner, BufferSizes::default(), thunk)
    }

    /// Construct a new `[Channel]` wrapping the full-duplex connection, `inner`.
    ///
    /// The fresh channel gets passed to `thunk`, and (barring any errors) the result of `thunk`
    /// gets returned by `with_sizes()`.
    ///
    /// # Buffering
    ///
    /// Because [`Channel`] uses a buffer (of size `sizes`) internally, it's
    /// preferable to pass an _unbuffered_ `inner` stream (such as a `TcpStream`).
    ///
    /// `with_sizes()` will flush any outgoing buffered data before returning.
    ///
    /// The channel should be _moved_ into `inner`, to avoid dropping a partial read buffer. See
    /// [`std::io::BufReader::into_inner`] for more info.
    ///
    /// # Example
    ///
    /// ```rust
    /// fn do_crypto_with_a_tcp_connection(conn: std::net::TcpStream) -> eyre::Result<()> {
    ///     swanky_channel::Channel::with_sizes(conn, Default::default(), |channel| {
    ///         channel.write_bytes(b"hello!")?;
    ///         Ok(())
    ///     })
    /// }
    /// ```
    pub fn with_sizes<C, T, F>(mut inner: C, sizes: BufferSizes, thunk: F) -> eyre::Result<T>
    where
        for<'a, 'b> F: FnOnce(&'a mut Channel<'b>) -> eyre::Result<T>,
        C: Read + Write,
    {
        let mut channel = Channel {
            read_buffer: vec![0; sizes.read.max(1)],
            read_buffer_pos: 0,
            read_buffer_len: 0,
            write_buffer: {
                let mut buf = Vec::new();
                buf.reserve_exact(sizes.write.max(1));
                buf
            },
            inner: &mut inner,
        };
        let t = thunk(&mut channel)?;
        channel.force_flush().wrap_err(NetworkError)?;
        Ok(t)
    }

    #[inline(never)]
    fn force_flush_slow(&mut self) -> eyre::Result<()> {
        self.inner
            .write_all(&self.write_buffer)
            .wrap_err(NetworkError)?;
        self.write_buffer.clear();
        self.inner.flush().wrap_err(NetworkError)?;
        Ok(())
    }

    /// Flush the channel
    ///
    /// Write buffers and [`Write::flush()`] the underlying channel.
    ///
    /// You shouldn't need to call this function in normal operation (since the channel will
    /// automatically insert flushes as needed).
    ///
    /// See the "Flushes" section in [`Channel`] for more information.
    #[inline]
    pub fn force_flush(&mut self) -> eyre::Result<()> {
        if !self.write_buffer.is_empty() {
            self.force_flush_slow()?;
        }
        Ok(())
    }
    #[inline(never)]
    fn write_bytes_slow(&mut self, bytes: &[u8]) -> eyre::Result<()> {
        let available = self.write_buffer.capacity() - self.write_buffer.len();
        debug_assert!(bytes.len() > available);
        self.force_flush()?;
        debug_assert!(self.write_buffer.is_empty());
        if bytes.len() > self.write_buffer.capacity() {
            self.inner.write_all(bytes).wrap_err(NetworkError)?;
            // We flush here because we use the length of the write_buffer to indicate whether
            // there are outstanding writes to flush. If we didn't flush here, then a long write
            // followed by a read would deadlock.
            self.inner.flush().wrap_err(NetworkError)?;
        } else {
            self.write_buffer.extend_from_slice(bytes);
        }
        Ok(())
    }
    /// Write all of `bytes` to the peer.
    ///
    /// If this function succeeds, all bytes have been written to the peer.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let mut dst = [0; 5];
    /// swanky_channel::local::local_channel_pair(
    ///     |c| c.read_bytes(&mut dst),
    ///     |c| c.write_bytes(b"hello"),
    /// )
    /// .unwrap();
    /// assert_eq!(dst.as_slice(), b"hello");
    /// ```
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> eyre::Result<()> {
        let available = self.write_buffer.capacity() - self.write_buffer.len();
        if available >= bytes.len() {
            self.write_buffer.extend_from_slice(bytes);
            Ok(())
        } else {
            self.write_bytes_slow(bytes)
        }
    }
    #[inline(never)]
    fn read_bytes_slow(&mut self, mut dst: &mut [u8]) -> eyre::Result<()> {
        while !dst.is_empty() {
            if self.read_buffer_len > 0 {
                let to_take = self.read_buffer_len.min(dst.len());
                let (filled, remaining) = dst.split_at_mut(to_take);
                dst = remaining;
                filled.copy_from_slice(
                    &self.read_buffer[self.read_buffer_pos..self.read_buffer_pos + to_take],
                );
                self.read_buffer_pos += to_take;
                self.read_buffer_len -= to_take;
            } else if dst.len() > self.read_buffer.len() {
                // Fill big reads from inner, directly.
                self.inner.read_exact(dst).wrap_err(NetworkError)?;
                return Ok(());
            } else {
                self.read_buffer_pos = 0;
                self.read_buffer_len = match self.inner.read(&mut self.read_buffer) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Hit unexpected EOF",
                        ))
                        .wrap_err(NetworkError)
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).wrap_err(NetworkError),
                };
            }
        }
        Ok(())
    }
    /// Read exactly of `dst.len()` bytes from the peer into `dst`.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let mut dst = [0; 5];
    /// swanky_channel::local::local_channel_pair(
    ///     |c| c.read_bytes(&mut dst),
    ///     |c| c.write_bytes(b"hello"),
    /// )
    /// .unwrap();
    /// assert_eq!(dst.as_slice(), b"hello");
    /// ```
    #[inline]
    pub fn read_bytes(&mut self, dst: &mut [u8]) -> eyre::Result<()> {
        self.force_flush()?;
        let read_buffer =
            &self.read_buffer[self.read_buffer_pos..self.read_buffer_pos + self.read_buffer_len];
        if let Some(src) = read_buffer.get(0..dst.len()) {
            dst.copy_from_slice(src);
            self.read_buffer_pos += dst.len();
            self.read_buffer_len -= dst.len();
            Ok(())
        } else {
            self.read_bytes_slow(dst)
        }
    }
    /// Read a `T` and deserialize it.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let (r, _) =
    ///     swanky_channel::local::local_channel_pair(|c| c.read::<i32>(), |c| c.write(&42_i32))
    ///         .unwrap();
    /// assert_eq!(r, 42);
    /// ```
    #[inline]
    pub fn read<T: CanonicalSerialize>(&mut self) -> eyre::Result<T> {
        let mut buf = GenericArray::<u8, T::ByteReprLen>::default();
        self.read_bytes(&mut buf)?;
        Ok(T::from_bytes(&buf)?)
    }
    /// Serialize `t` and [`Self::write_bytes()`] it over the wire.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let (r, _) =
    ///     swanky_channel::local::local_channel_pair(|c| c.read::<i32>(), |c| c.write(&42_i32))
    ///         .unwrap();
    /// assert_eq!(r, 42);
    /// ```
    #[inline]
    pub fn write<T: CanonicalSerialize>(&mut self, t: &T) -> eyre::Result<()> {
        self.write_bytes(&t.to_bytes())
    }
}

#[cfg(test)]
mod tests;
