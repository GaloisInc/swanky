use scuttlebutt::AbstractChannel;
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

    fn read_one_byte(&mut self) -> u8 {
        self.curr += 1;
        if self.curr >= self.read_buffer.len() {
            let msg = self.websocket.read().unwrap();
            match msg {
                Message::Binary(m) => {
                    self.read_buffer = m;
                    self.curr = 0;
                }
                _ => {
                    unimplemented!()
                }
            }
        }

        let r = self.read_buffer[self.curr];
        r
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
        if self.write_buffer.len() > 0 {
            let msg = Message::binary(&self.write_buffer[0..self.write_buffer_len]);
            self.websocket.write(msg).unwrap();
        }
        self.write_buffer_len = 0;
    }
}

impl<Stream: Read + Write> AbstractChannel for WsChannel<Stream> {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()> {
        for i in 0..bytes.len() {
            bytes[i] = self.read_one_byte();
        }
        Ok(())
    }

    /// Write a slice of `u8`s to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        for b in bytes {
            self.write_one_byte(*b)?;
        }
        Ok(())
    }
    /// Flush the channel.
    fn flush(&mut self) -> Result<()> {
        self.internal_flush();
        Ok(())
    }
    /// Clone the channel.
    fn clone(&self) -> Self {
        unimplemented!();
    }
}
