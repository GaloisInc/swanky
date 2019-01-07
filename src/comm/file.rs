use super::{BinaryReceive, BinarySend};

use failure::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::transmute;

impl BinarySend for File {
    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        let bytes: [u8; 8] = unsafe { transmute((data.len() as u64).to_be()) };
        self.write_all(&bytes)?;
        self.write_all(&data)?;
        Ok(())
    }
}

impl BinaryReceive for File {
    fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let mut bytes: [u8; 8] = Default::default();
        self.read_exact(&mut bytes)?;
        let len = unsafe { u64::from_be(transmute(bytes)) as usize };
        let mut v = Vec::with_capacity(len);
        v.resize(len, 0);
        self.read_exact(&mut v)?;
        Ok(v)
    }
}
