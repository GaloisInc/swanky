pub mod dummy;
pub mod np;

use std::io::Error;

pub trait ObliviousTransfer {
    fn send(&mut self, values: Vec<u128>) -> Result<(), Error>;
    fn receive(&mut self, input: usize) -> Result<u128, Error>;
}
