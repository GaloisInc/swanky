mod alsz;
mod chou_orlandi;
mod dummy;
mod iknp;
mod naor_pinkas;

pub use alsz::AlszOT;
pub use chou_orlandi::ChouOrlandiOT;
pub use dummy::DummyOT;
pub use iknp::IknpOT;
pub use naor_pinkas::NaorPinkasOT;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use failure::Error;
use std::io::Error as IOError;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait ObliviousTransfer<T: Read + Write + Send> {
    fn new(stream: Arc<Mutex<T>>) -> Self;
    fn send(&mut self, values: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error>;
    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error>;
}

struct Stream<T: Read + Write + Send> {
    stream: Arc<Mutex<T>>,
}

impl<T: Read + Write + Send> Stream<T> {
    pub fn new(stream: Arc<Mutex<T>>) -> Self {
        Self { stream }
    }
    #[inline(always)]
    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream()
            .write(pt.compress().as_bytes())
            .map_err(Error::from)
    }
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => {
                return Err(Error::from(IOError::new(
                    ErrorKind::InvalidData,
                    "Unable to decompress point",
                )));
            }
        };
        Ok(pt)
    }
    #[inline(always)]
    fn write_bool(&mut self, b: bool) -> Result<usize, Error> {
        self.stream().write(&[b as u8]).map_err(Error::from)
    }
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool, Error> {
        let mut data = [0; 1];
        self.stream().read_exact(&mut data)?;
        Ok(data[0] != 0)
    }
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.stream().write(bytes).map_err(Error::from)
    }
    #[inline(always)]
    fn read_bytes(&mut self, nbytes: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0; nbytes];
        self.stream().read_exact(&mut v)?;
        Ok(v)
    }
    #[inline(always)]
    fn read_bytes_inplace(&mut self, mut bytes: &mut [u8]) -> Result<(), Error> {
        self.stream().read_exact(&mut bytes)?;
        Ok(())
    }
}
