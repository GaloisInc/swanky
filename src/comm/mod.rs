use failure::Error;

pub mod file;
pub mod tcp;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Result<Vec<u8>, Error>;
}
