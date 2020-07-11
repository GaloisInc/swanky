
//! Puncturable Pseudo-Random Function (PPRF) traits
//!
//! This module provides traits for PPRF

pub mod pprf;
#[allow(unused_imports)]
use rand::{CryptoRng, Rng};
#[allow(unused_imports)]
use scuttlebutt::{AbstractChannel, Block};
pub use bit_vec::BitVec;
//TODO: change this type to field type later
pub type Fpr = Block;
pub type Fpr2 = (Fpr, Fpr);
#[path = "../errors.rs"]
pub mod errors;
use crate::pprf::errors::Error;

// PPRF 
pub trait PPRF{
    /// Key generation.
    fn keygen(lambda:BitVec) -> BitVec;
    /// Compute puncture key at a point x.
    fn puncture(k:BitVec, x:BitVec) -> Vec <BitVec>;
    /// Evaluate at a point x given the punctured key.
    fn eval(pk: Vec<BitVec>, z:BitVec) -> Option<Vec<BitVec>>;
}

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
        inputs: &[(Block, Block, Block)],
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
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
    fn puncture(keys: Vec<BitVec>, alpha: bool) -> BitVec;
    fn fulleval(pkey: BitVec, alpha:bool) -> Vec<BitVec>;
    fn verify(gamma: &[u8], alpha:u32) -> Option<u32>;
}