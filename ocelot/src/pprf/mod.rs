
//! Puncturable Pseudo-Random Function (PPRF) traits
//!
//! This module provides traits for PPRF

pub mod pprf;
pub mod tpprf;

use crate::errors::Error;

#[allow(unused_imports)]
use rand::{CryptoRng, Rng};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block, Block512};
pub use bit_vec::BitVec;
// finite fields
//use ff::*;
//TODO: change this type to field type later
//pub type Fpr = BitIterator<Block>;
pub type Fpr = Block;
pub type Fpr2 = (Fpr, Fpr);

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

/// A trait for PPRF Receiver
pub trait PprfReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        input1: &[(Block, Block)],
        input2: &(Block, Block),
        input3: &Block512,
        rng: &mut RNG,
    ) -> Option<(Vec<Block>, (Block, Block))>;
}