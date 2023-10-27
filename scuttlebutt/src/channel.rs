mod hash_channel;
mod sync_channel;
mod track_channel;
#[cfg(unix)]
mod unix_channel;

pub use hash_channel::HashChannel;
pub use sync_channel::SyncChannel;
pub use track_channel::TrackChannel;

#[cfg(unix)]
pub use unix_channel::{track_unix_channel_pair, unix_channel_pair, TrackUnixChannel, UnixChannel};

use crate::{serialization::CanonicalSerialize, Block, Block512};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use generic_array::GenericArray;
use std::{
    cell::RefCell,
    io::{Read, Result, Write},
    rc::Rc,
};

/// A trait for managing I/O. `AbstractChannel`s are clonable, and provide basic
/// read/write capabilities for both common and scuttlebutt-specific types.
pub trait AbstractChannel {
    /// Read a slice of `u8`s from the channel.
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
    /// Write a slice of `u8`s to the channel.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;
    /// Flush the channel.
    fn flush(&mut self) -> Result<()>;
    /// Clone the channel.
    fn clone(&self) -> Self
    where
        Self: Sized;
    /// Read `nbytes` from the channel, and return it as a `Vec`.
    fn read_vec(&mut self, nbytes: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; nbytes];
        self.read_bytes(&mut data)?;
        Ok(data)
    }

    /// Write a `bool` to the channel.
    #[inline(always)]
    fn write_bool(&mut self, b: bool) -> Result<()> {
        self.write_bytes(&[b as u8])?;
        Ok(())
    }

    /// Read a `bool` from the channel.
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool> {
        let mut data = [0u8; 1];
        self.read_bytes(&mut data)?;
        Ok(data[0] != 0)
    }

    /// Write a `u8` to the channel.
    #[inline(always)]
    fn write_u8(&mut self, s: u8) -> Result<()> {
        let data = [s];
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read a `u8` from the channel.
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut data = [0];
        self.read_bytes(&mut data)?;
        Ok(data[0])
    }

    /// Write a `u16` to the channel.
    #[inline(always)]
    fn write_u16(&mut self, s: u16) -> Result<()> {
        let data: [u8; 2] = s.to_le_bytes();
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read a `u16` from the channel.
    #[inline(always)]
    fn read_u16(&mut self) -> Result<u16> {
        let mut data = [0u8; 2];
        self.read_bytes(&mut data)?;
        let s = u16::from_le_bytes(data);
        Ok(s)
    }

    /// Write a `u32` to the channel.
    #[inline(always)]
    fn write_u32(&mut self, s: u32) -> Result<()> {
        let data: [u8; 4] = s.to_le_bytes();
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read a `u32` from the channel.
    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32> {
        let mut data = [0u8; 4];
        self.read_bytes(&mut data)?;
        let s = u32::from_le_bytes(data);
        Ok(s)
    }

    /// Write a `u64` to the channel.
    #[inline(always)]
    fn write_u64(&mut self, s: u64) -> Result<()> {
        let data: [u8; 8] = s.to_le_bytes();
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read a `u64` from the channel.
    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64> {
        let mut data = [0u8; 8];
        self.read_bytes(&mut data)?;
        let s = u64::from_le_bytes(data);
        Ok(s)
    }

    /// Write a `usize` to the channel.
    #[inline(always)]
    fn write_usize(&mut self, s: usize) -> Result<()> {
        self.write_u64(s as u64)
    }

    /// Read a `usize` from the channel.
    #[inline(always)]
    fn read_usize(&mut self) -> Result<usize> {
        let x = self.read_u64()?;
        usize::try_from(x).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Write a `Block` to the channel.
    #[inline(always)]
    fn write_block(&mut self, b: &Block) -> Result<()> {
        self.write_bytes(b.as_ref())?;
        Ok(())
    }

    /// Read a `Block` from the channel.
    #[inline(always)]
    fn read_block(&mut self) -> Result<Block> {
        let mut v = Block::default();
        self.read_bytes(v.as_mut())?;
        Ok(v)
    }

    /// Read `n` `Block`s from the channel.
    #[inline(always)]
    fn read_blocks(&mut self, n: usize) -> Result<Vec<Block>> {
        (0..n).map(|_| self.read_block()).collect()
    }

    /// Write a `Block512` to the channel.
    #[inline(always)]
    fn write_block512(&mut self, b: &Block512) -> Result<()> {
        self.write_bytes(b.as_ref())
    }

    /// Read a `Block512` from the channel.
    #[inline(always)]
    fn read_block512(&mut self) -> Result<Block512> {
        let mut out = Block512::default();
        self.read_bytes(out.as_mut())?;
        Ok(out)
    }

    /// Write a `RistrettoPoint` to the channel.
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<()> {
        self.write_bytes(pt.compress().as_bytes())?;
        Ok(())
    }

    /// Read a `RistrettoPoint` from the channel.
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint> {
        let mut data = [0u8; 32];
        self.read_bytes(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .decompress()
        {
            Some(pt) => pt,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unable to decompress ristretto point",
                ));
            }
        };
        Ok(pt)
    }

    /// Read a `CanonicalSerialize` object from the channel.
    fn read_serializable<E: CanonicalSerialize>(&mut self) -> Result<E> {
        let mut buf = GenericArray::<u8, E::ByteReprLen>::default();
        self.read_bytes(&mut buf[..])?;
        let fe = match E::from_bytes(&buf) {
            Ok(fe) => fe,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };
        Ok(fe)
    }

    /// Write a `CanonicalSerialize` object to the channel.
    fn write_serializable<E: CanonicalSerialize>(&mut self, x: &E) -> Result<()> {
        self.write_bytes(&x.to_bytes())?;
        Ok(())
    }
}

impl AbstractChannel for swanky_channel::Channel<'_> {
    #[inline]
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<()> {
        swanky_channel::Channel::read_bytes(self, bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        swanky_channel::Channel::write_bytes(self, bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.force_flush()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

/// A standard read/write channel that implements `AbstractChannel`.
pub struct Channel<R, W> {
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

impl<R: Read, W: Write> Channel<R, W> {
    /// Make a new `Channel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Rc::new(RefCell::new(reader));
        let writer = Rc::new(RefCell::new(writer));
        Self { reader, writer }
    }

    /// Return a reader object wrapped in `Rc<RefCell>`.
    pub fn reader(self) -> Rc<RefCell<R>> {
        self.reader
    }

    /// Return a writer object wrapped in `Rc<RefCell>`.
    pub fn writer(self) -> Rc<RefCell<W>> {
        self.writer
    }
}

impl<R: Read, W: Write> AbstractChannel for Channel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.borrow_mut().write_all(bytes)?;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.borrow_mut().read_exact(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.writer.borrow_mut().flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}

/// Standard Read/Write channel built from a symmetric stream.
pub struct SymChannel<S> {
    stream: Rc<RefCell<S>>,
}

impl<S: Read + Write> SymChannel<S> {
    /// Make a new `Channel` from a stream.
    pub fn new(stream: S) -> Self {
        let stream = Rc::new(RefCell::new(stream));
        Self { stream }
    }
}

impl<S: Read + Write> AbstractChannel for SymChannel<S> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.borrow_mut().write_all(bytes)?;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.stream.borrow_mut().read_exact(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.stream.borrow_mut().flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
        }
    }
}
