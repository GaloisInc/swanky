use std::{cell::RefCell, io::Result};

use scuttlebutt::{field::FiniteField, AbstractChannel};

#[derive(Debug, Clone)]
pub struct TxChannel<C: AbstractChannel> {
    pub ch: C,
    pub tx: RefCell<blake3::Hasher>,
}

impl<C: AbstractChannel> AbstractChannel for TxChannel<C> {
    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        Self {
            ch: self.ch.clone(),
            tx: self.tx.clone(),
        }
    }

    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        self.ch.read_bytes(buf)?;
        self.tx.borrow_mut().update(buf);
        Ok(())
    }

    fn write_bytes(&mut self, buf: &[u8]) -> Result<()> {
        self.tx.borrow_mut().update(buf);
        self.ch.write_bytes(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.ch.flush()
    }
}

impl<C: AbstractChannel> TxChannel<C> {
    pub fn new(ch: C, tx: RefCell<blake3::Hasher>) -> Self {
        Self { ch, tx }
    }

    pub fn challenge<F: FiniteField>(&mut self) -> F {
        let mut tx = self.tx.borrow_mut();
        let hsh = tx.finalize();
        let hsh = hsh.as_bytes();
        let fld = F::from_uniform_bytes(&hsh[..16].try_into().unwrap());
        tx.update(&[0]);
        fld
    }
}
