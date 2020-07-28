
// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Puncturable PRF (PPRF) Traits
//!
//! This module provides traits for Puncturable Pseudo-Random Functions

pub mod pprf;
pub mod tpprf;

#[allow(unused_imports)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use scuttlebutt::{AbstractChannel, Block};
use crate::field::Fp;
use rand::{CryptoRng, Rng};


pub type Fp2 = (Fp, Fp);
pub type PprfRange = (Fp2, Block);
pub type Fpstar = Fp;

/// A PPRF trait. 
pub trait PPRF{
    /// Key generation.
    fn keygen(lambda:Block) -> Block;
    /// Compute puncture key at a point x.
    fn puncture(k:Block, x:Block) -> Vec<Block>;
    /// length doubling PRG G
    fn prg_g<RNG: CryptoRng + Rng>(seed:Block, rng:&mut RNG) -> (Block, Block);
    /// PRG G': used to compute the PRF outputs on the last level of the tree.
    fn prg_gprime<RNG: CryptoRng + Rng>(seed:Block, rng:&mut RNG) -> PprfRange;
    /// Evaluate at a point x given the punctured key.
    fn eval(pk:Vec<Block>, z:Block) -> Option<Vec<Block>>;
    /// Puncturestar
    fn puncture_star(keys:Vec<Block>, alpha:Block) -> Vec<Block>;
    fn full_eval(kstar: Vec<Block>, alpha: Block) -> Vec<PprfRange>;
}


/// A trait for PPRF Sender.
pub trait PprfSender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init() -> Result<Self, Error>;
    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        beta: (Fp, Fp),
    ) -> Result<Block, Error>;
}

/// A trait for PPRF Receiver
pub trait PprfReceiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    fn init() -> Result<Self, Error>;
    
    fn receive<C:AbstractChannel>(
        &mut self,
        channel: &mut C,
        alpha: Block
    ) -> Option<(Vec<Block>, (Fp, Fp))> ;
}

/// A trait for tPPRF Sender
pub trait Tpprfsender
where 
    Self: Sized,
    {
        fn init() -> Result<Self, Error>;
        fn send<C: AbstractChannel>(
            &mut self,
            channel: &mut C,
            x:Fp
        ) -> Result<(), Error>;
    }

/// A trait for tPPRF Receiver
pub trait Tpprfreceiver
where 
    Self: Sized
 {
    fn init() -> Result<Self, Error>;
    fn receive<C:AbstractChannel>(
        &mut self,
        channel: &mut C,
        s: Vec<Block>,
        y: Vec<Fpstar>
    ) -> Option <(Vec<Block>, Vec<Block>, Vec<Block>, Vec<Fpstar>)>;
 }

 