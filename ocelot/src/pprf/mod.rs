
//! Puncturable Pseudo-Random Function (PPRF) traits
//!
//! This module provides traits for PPRF

pub mod pprf;
//pub mod tpprf;

#[allow(unused_imports)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use scuttlebutt::{AbstractChannel, Block};
//pub use bit_vec::BitVec;
use crate::field::Fp;

pub type Fp2 = (Fp, Fp);

/*// PPRF 
pub trait PPRF{
    /// Key generation.
    fn keygen(lambda:BitVec) -> BitVec;
    /// Compute puncture key at a point x.
    fn puncture(k:BitVec, x:BitVec) -> Vec <BitVec>;
    /// Evaluate at a point x given the punctured key.
    fn eval(pk: Vec<BitVec>, z:BitVec) -> Option<Vec<BitVec>>;
}*/

/// A trait for PPRF Sender
pub trait PprfSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init(&mut self) -> Result<(), Error>;

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        beta: (Fp, Fp),
        kpprf: Block
    ) -> Result<(), Error>;
}

/// A trait for PPRF Receiver
pub trait PprfReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init<C: AbstractChannel>(
        &mut self, 
        channel: &mut C
    ) -> Result<Self, Error>;
    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        alpha: Block
    ) -> Option<(Vec<Block>, (Fp, Fp))>;
}

/// A trait for tPPRF Sender
pub trait Tpprfsender
where 
    Self: Sized,
    {
        fn init() -> Result<Self, Error>;
        fn send() -> Result<(), Error>;
    }

/// A trait for tPPRF Receiver
pub trait Tpprfreceiver
where 
    Self: Sized
 {
    fn init() -> Result<(), Error>;
 }
