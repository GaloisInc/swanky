pub mod iknp;

use crate::base::ObliviousTransfer;
use std::io::{Error, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait OTExtension<OT: ObliviousTransfer> {
    fn send(&mut self, values: Vec<(u128, u128)>) -> Result<(), Error>;
    fn receive(&mut self, input: Vec<bool>) -> Result<Vec<u128>, Error>;
}

struct Stream<T: Read + Write> {
    stream: Arc<Mutex<T>>,
}

impl<T: Read + Write> Stream<T> {
    pub fn new(stream: T) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        Self { stream }
    }
    #[inline(always)]
    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }
    #[inline(always)]
    fn write_u128(&mut self, data: &u128) -> Result<usize, Error> {
        self.stream().write(&data.to_ne_bytes())
    }
    #[inline(always)]
    fn read_u128(&mut self) -> Result<u128, Error> {
        let mut data = [0; 16];
        self.stream().read_exact(&mut data)?;
        Ok(u128::from_ne_bytes(data))
    }
}
