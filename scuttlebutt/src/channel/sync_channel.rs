use crate::AbstractChannel;
use std::{
    io::{Read, Result, Write},
    sync::{Arc, Mutex},
};

/// A channel that implements `AbstractChannel` as well as `Send` and `Sync`.
pub struct SyncChannel<R, W> {
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
}

impl<R: Read, W: Write> SyncChannel<R, W> {
    /// Make a new `Channel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));
        Self { reader, writer }
    }

    /// Return a reader object wrapped in `Arc<Mutex<R>>`.
    pub fn reader(self) -> Arc<Mutex<R>> {
        self.reader
    }

    /// Return a writer object wrapped in `Arc<Mutex<W>>`.
    pub fn writer(self) -> Arc<Mutex<W>> {
        self.writer
    }
}

impl<R: Read, W: Write> AbstractChannel for SyncChannel<R, W> {
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.lock().unwrap().write_all(bytes)?;
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.reader.lock().unwrap().read_exact(&mut bytes)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.writer.lock().unwrap().flush()
    }

    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}
