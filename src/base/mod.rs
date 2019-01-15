pub mod dummy;
pub mod naor_pinkas;
pub mod chou_orlandi;

use std::io::{Error, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

pub trait ObliviousTransfer {
    fn send(&mut self, values: Vec<u128>) -> Result<(), Error>;
    fn receive(&mut self, input: usize) -> Result<u128, Error>;
}

struct EllipticCurveOT<T: Read + Write> {
    stream: Arc<Mutex<T>>
}

impl<T: Read + Write> EllipticCurveOT<T>
{
    pub fn new(stream: T) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        Self { stream }
    }

    #[inline(always)]
    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream().write(pt.compress().as_bytes())
    }
    #[inline(always)]
    fn write_u128(&mut self, data: &u128) -> Result<usize, Error> {
        self.stream().write(&data.to_ne_bytes())
    }
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => return Err(Error::new(ErrorKind::InvalidData, "Unable to decompress point")),
        };
        Ok(pt)
    }
    #[inline(always)]
    fn read_u128(&mut self) -> Result<u128, Error> {
        let mut data = [0; 16];
        self.stream().read_exact(&mut data)?;
        Ok(u128::from_ne_bytes(data))
    }
    #[inline(always)]
    fn hash_pt(&mut self, pt: &RistrettoPoint) -> u128 {
        let pt = pt.compress();
        u128::from_ne_bytes(*array_ref!(pt.as_bytes(), 0, 16))
    }
}
