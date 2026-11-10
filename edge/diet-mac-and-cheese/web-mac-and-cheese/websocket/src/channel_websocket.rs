use std::io::Result;
use std::io::{Read, Write};
use tungstenite::Message;
use tungstenite::WebSocket;

pub struct WsChannel<Stream> {
    websocket: WebSocket<Stream>,
    read_buffer: Vec<u8>,
    curr: usize,
    write_buffer: Vec<u8>,
    write_buffer_len: usize,
}

const BUFFER_SIZE: usize = 1_000_000;

impl<Stream: Read + Write> WsChannel<Stream> {
    pub fn new(websocket: WebSocket<Stream>) -> Self {
        WsChannel {
            websocket,
            read_buffer: Vec::new(),
            curr: 0,
            write_buffer: vec![0u8; BUFFER_SIZE],
            write_buffer_len: 0,
        }
    }

    /// Blocks until the next non-empty binary message is buffered.
    fn fill_read_buffer(&mut self) -> Result<()> {
        while self.curr >= self.read_buffer.len() {
            match self.websocket.read().map_err(std::io::Error::other)? {
                Message::Binary(m) => {
                    self.read_buffer = m.to_vec();
                    self.curr = 0;
                }
                _ => {
                    unimplemented!()
                }
            }
        }

        Ok(())
    }

    fn write_one_byte(&mut self, b: u8) -> Result<()> {
        self.write_buffer[self.write_buffer_len] = b;
        self.write_buffer_len += 1;
        if self.write_buffer_len >= BUFFER_SIZE {
            self.internal_flush();
        }
        Ok(())
    }

    fn internal_flush(&mut self) {
        if !self.write_buffer.is_empty() {
            let msg = Message::binary(self.write_buffer[0..self.write_buffer_len].to_vec());
            self.websocket.write(msg).unwrap();
            self.websocket.flush().unwrap();
        }
        self.write_buffer_len = 0;
    }
}

impl<Stream: Read + Write> Read for WsChannel<Stream> {
    /// Read up to `bytes.len()` bytes from the channel.
    ///
    /// Only blocks for a single websocket message, returning a short
    /// read if `bytes` is not filled.
    /// This avoids a deadlock when the peer sends less data than
    /// requested.
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        self.fill_read_buffer()?;
        let n = (self.read_buffer.len() - self.curr).min(bytes.len());
        bytes[..n].copy_from_slice(&self.read_buffer[self.curr..self.curr + n]);
        self.curr += n;

        Ok(n)
    }
}

impl<Stream: Read + Write> Write for WsChannel<Stream> {
    /// Write a slice of `u8`s to the channel.
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        for b in bytes {
            self.write_one_byte(*b)?;
        }
        Ok(bytes.len())
    }

    /// Flush the channel.
    fn flush(&mut self) -> Result<()> {
        self.internal_flush();
        Ok(())
    }
}
