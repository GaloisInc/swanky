use crate::errors::Error;
use scuttlebutt::{AbstractChannel, Block};
use rand::{CryptoRng, Rng};

pub mod rev_vole;

/// A trait for Reverse VOLE sender
pub trait Rvolesender 
where 
    Self: Sized,
{
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<(), Error>;
}

pub trait Rvolereceiver
where 
    Self: Sized,
    {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<(), Error>;

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Block>, Vec<Block>), Error>;
}
    
