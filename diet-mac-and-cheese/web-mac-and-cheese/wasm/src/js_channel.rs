use scuttlebutt::AbstractChannel;
use wasm_bindgen::prelude::*;

// TODO: We should experiment with an API that exchange vector of data instead individual bytes to minimize
// the amount of FFI calls. That's already done with `js_write_byte/js_write_bytes`. For `js_read_byte` it is
// more difficult because the signature would be `js_read_bytes() -> Vec[u8]` returning a vector of some form and it
// is not clear to do that or even if it is worth doing such optimization since the majority of data communicated is
// from the prover to the verifier and not the other way around.
#[wasm_bindgen]
extern "C" {
    pub fn js_read_byte() -> u8;
    pub fn js_write_byte(b: u8);
    pub fn js_write_bytes(bytes: &[u8]);
    pub fn js_flush();
}

#[wasm_bindgen]
extern "C" {
    pub fn print_console(b: u8);
}

pub struct ShimChannel {
    read_buffer: u8,
    _curr: usize, // this is currently unused because the interface reads one byte at a time. see TODO above
    write_buffer: Vec<u8>,
    write_buffer_len: usize,
}

// Warning!! This buffer size should be smaller than the SharedBuffer in JS,
// otherwise there is a risk that more data is written than can fit in the SharedBuffer.
const BUFFER_SIZE: usize = 3_000_000;

impl ShimChannel {
    pub fn new() -> Self {
        ShimChannel {
            read_buffer: 0,
            _curr: 0,
            write_buffer: vec![0u8; BUFFER_SIZE],
            write_buffer_len: 0,
        }
    }

    fn read_one_byte(&mut self) -> u8 {
        self.read_buffer = js_read_byte();
        self.read_buffer
    }

    fn write_one_byte(&mut self, b: u8) {
        self.write_buffer[self.write_buffer_len] = b;
        self.write_buffer_len += 1;
        if self.write_buffer_len >= BUFFER_SIZE {
            self.internal_flush();
        }
    }

    fn internal_flush(&mut self) {
        if self.write_buffer_len > 0 {
            js_write_bytes(&self.write_buffer[0..self.write_buffer_len]);
            //for i in 0..self.write_buffer_len {
            //    js_write_byte(self.write_buffer[i])
            //}
        }

        // reset buffer
        self.write_buffer_len = 0;

        js_flush();
    }
}

impl AbstractChannel for ShimChannel {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        for i in 0..bytes.len() {
            bytes[i] = self.read_one_byte();
        }
        Ok(())
    }

    /// Write a slice of `u8`s to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        for b in bytes {
            self.write_one_byte(*b);
        }
        Ok(())
    }
    /// Flush the channel.
    fn flush(&mut self) -> std::io::Result<()> {
        self.internal_flush();
        Ok(())
    }
    /// Clone the channel.
    fn clone(&self) -> Self {
        unimplemented!()
    }
}
