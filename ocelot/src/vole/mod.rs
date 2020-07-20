#![allow(unused_imports)]
use crate::errors::Error;
use scuttlebutt::{AbstractChannel, Block};
use rand::{CryptoRng, Rng};

pub mod rev_vole;
pub type Fpr = Block;
pub type Fp = Block;
/// A trait for Reverse VOLE sender
pub trait Rvolesender 
where 
    Self: Sized,
{
    fn init() -> Result<Self, Error>;

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C
    ) -> Result<(), Error>;
}

pub trait Rvolereceiver
where 
    Self: Sized,
    {
    fn init<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<Self, Error>;

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &Vec<Fpr>
    ) -> Result<(Vec<Fpr>, Vec<Fpr>), Error>;
}
    
