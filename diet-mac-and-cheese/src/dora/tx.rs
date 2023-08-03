use std::io::Result;

use scuttlebutt::{field::FiniteField, AbstractChannel};

#[derive(Debug)]
pub struct TxChannel<'a, C: AbstractChannel> {
    pub ch: C,
    pub tx: &'a mut blake3::Hasher,
}

impl<'a, C: AbstractChannel> AbstractChannel for TxChannel<'a, C> {
    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        unimplemented!("Fiat-Shamir channel does not allow cloning")
    }

    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        self.ch.read_bytes(buf)?;
        self.tx.update(buf);
        Ok(())
    }

    fn write_bytes(&mut self, buf: &[u8]) -> Result<()> {
        self.tx.update(buf);
        self.ch.write_bytes(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.ch.flush()
    }
}

impl<'a, C: AbstractChannel> TxChannel<'a, C> {
    pub fn new(ch: C, tx: &'a mut blake3::Hasher) -> Self {
        Self { ch, tx }
    }

    pub fn challenge<F: FiniteField>(&mut self) -> F {
        let mut buf: [u8; 16] = [0u8; 16];
        self.tx.finalize_xof().fill(&mut buf);
        let chl = F::from_uniform_bytes(&buf);
        self.tx.update(&[0]);
        chl
    }
}
