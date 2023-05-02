use std::io::{Read, Write};

use scuttlebutt::AbstractChannel;

pub struct ChannelAdapter<C: Read + Write>(pub C);
impl<C: Read + Write> AbstractChannel for ChannelAdapter<C> {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        self.0.read_exact(bytes)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_all(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }

    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
}
