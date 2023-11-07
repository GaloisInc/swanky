//! Utilities for constructing intra-process channels and sockets.
//!
//! These should primarily be used for testing purposes.

use std::io::{Read, Write};

use eyre::Context;

use crate::Channel;

#[cfg(any(test, not(unix)))]
fn tcp_socketpair() -> eyre::Result<(std::net::TcpStream, std::net::TcpStream)> {
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(1);
    // Port 0 means the OS will pick an unused port.
    let server = std::net::TcpListener::bind("127.0.0.1:0").wrap_err("binding to 'localhost:0'")?;
    let addr = server.local_addr().wrap_err("getting local_addr()")?;
    let thread = std::thread::spawn(move || std::net::TcpStream::connect_timeout(&addr, TIMEOUT));
    // If something goes wrong, we don't want to hang forever. There doesn't seem to be an accept()
    // timeout in Rust's standard library. We simulate one with sleeping and non-blocking IO.
    const SLEEP_STEP: Duration = Duration::from_micros(250);
    const NUM_STEPS: u128 = TIMEOUT.as_micros() / SLEEP_STEP.as_micros();
    server
        .set_nonblocking(true)
        .wrap_err("set nonblocking on server")?;
    for _ in 0..NUM_STEPS {
        match server.accept() {
            Ok((conn1, _)) => {
                let conn2 = thread
                    .join()
                    .expect("thread didn't panic")
                    .wrap_err("connect() failed from thread")?;
                // On some platforms, the accepted connections start off as non-blocking.
                server
                    .set_nonblocking(false)
                    .wrap_err("undo nonblocking on server")?;
                conn1
                    .set_nonblocking(false)
                    .wrap_err("undo nonblocking on client")?;
                conn2
                    .set_nonblocking(false)
                    .wrap_err("undo nonblocking on client")?;
                return Ok((conn1, conn2));
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(e).wrap_err("accept() failed with a non-timeout-related error");
                }
            }
        }
        std::thread::sleep(SLEEP_STEP);
    }
    eyre::bail!("Failed to accept() connection in {TIMEOUT:?}");
}

/// An intra-process socket
///
/// Prefer using this type to an intra-process unix stream, since this type will work on targets
/// which don't support unix sockets.
pub struct LocalSocket {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixStream,
    #[cfg(not(unix))]
    inner: std::net::TcpStream,
}
impl LocalSocket {
    /// Create a new `LocalSocket` pair.
    ///
    /// Data written on one half of the pair will be read by the other side (and vice-versa; the
    /// socket is full-duplex).
    ///
    /// # Example
    /// ```
    /// use std::io::{Read, Write};
    /// use swanky_channel::local::LocalSocket;
    /// let (mut a, mut b) = LocalSocket::pair().unwrap();
    /// let handle = std::thread::spawn(move || b.write_all(b"hello"));
    /// let mut buf = [0; 5];
    /// a.read_exact(&mut buf).unwrap();
    /// assert_eq!(&buf, b"hello");
    /// handle.join().unwrap().unwrap();
    /// ```
    pub fn pair() -> eyre::Result<(Self, Self)> {
        #[cfg(unix)]
        let (a, b) = std::os::unix::net::UnixStream::pair().context("Constructing LocalSocket")?;
        #[cfg(not(unix))]
        let (a, b) = tcp_socketpair().context("Constructing LocalSocket")?;
        Ok((LocalSocket { inner: a }, LocalSocket { inner: b }))
    }
}
impl Read for LocalSocket {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for LocalSocket {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Run `side_f` and `side_g` in separate threads connected by a [`Channel`].
///
/// # Example
/// ```
/// use swanky_channel::Channel;
/// let (a, b) = swanky_channel::local::local_channel_pair(
///     |c| {
///         let out = c.read::<i32>()?;
///         c.write(&42_i32)?;
///         Ok(out)
///     },
///     |c| {
///         c.write(&42_i32)?;
///         let out = c.read::<i32>()?;
///         Ok(out)
///     },
/// )
/// .unwrap();
/// assert_eq!(a, 42);
/// assert_eq!(b, 42);
/// ```
pub fn local_channel_pair<T, U: Send, F, G>(side_f: F, side_g: G) -> eyre::Result<(T, U)>
where
    for<'a, 'b> F: FnOnce(&'b mut Channel<'a>) -> eyre::Result<T>,
    for<'a, 'b> G: Send + FnOnce(&'b mut Channel<'a>) -> eyre::Result<U>,
{
    std::thread::scope(|scope| {
        let (f_sock, g_sock) = LocalSocket::pair()?;
        let handle = scope.spawn(move || Channel::with(g_sock, side_g));
        // Unwrap will cause this thread to panic if g() panics.
        let f_result = Channel::with(f_sock, side_f);
        let g_result = handle.join().unwrap();
        match (f_result, g_result) {
            (Ok(f), Ok(g)) => Ok((f, g)),
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e),
            (Err(f), Err(g)) => Err(f.wrap_err(g)),
        }
    })
}

#[test]
fn test_tcpsocketpair() {
    use std::time::Duration;
    let (mut a, mut b) = tcp_socketpair().unwrap();
    for s in [&mut a, &mut b] {
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    }
    fn communicate(r: &mut std::net::TcpStream, w: &mut std::net::TcpStream, msg: &[u8]) {
        // No need for threads. These messages are short enough to fit in the Kernel buffer.
        w.write_all(msg).unwrap();
        w.flush().unwrap();
        let mut buf = [0; 256];
        r.read_exact(&mut buf[0..msg.len()]).unwrap();
        assert_eq!(&buf[0..msg.len()], msg);
    }
    communicate(&mut a, &mut b, b"Hello, there!");
    communicate(&mut b, &mut a, b"General Kenobi!");
    communicate(&mut a, &mut b, b"I have the high ground");
}
