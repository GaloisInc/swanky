#![allow(unused_imports)]
use crate::errors::Error;
use scuttlebutt::{AbstractChannel, Block};
use rand::{CryptoRng, Rng};
use crate::field::{Fp, FpRepr};
pub mod rev_vole;

/// Sender inputs ((beta, chi), (b, x)).
type SenderDom = ((Vec<Fp>, Fp), (Vec<Fp>, Fp));
/// Receiver input is a vector y.
type ReceiverDom = Vec<Fp>;
/// A trait for Reverse VOLE sender
pub trait Rvolesender 
where 
    Self: Sized,
{
    
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: SenderDom
    ) -> Result<(), Error>;
}

pub trait Rvolereceiver
where 
    Self: Sized,
    {
    
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: ReceiverDom
    ) -> Result<(Vec<Fp>, Vec<Fp>), Error>;
}
    
