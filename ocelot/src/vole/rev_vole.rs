// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of reverse VOLE functionality presented in 
//! (<https://eprint.iacr.org/2019/1159>, Fig.14 page 25)
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, AesRng};
use crate::errors::Error;
use std::arch::x86_64::*;

/// Reverse VOLE parameters
pub struct Params;

/// Initialize parameters
impl Params {
    pub const T: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const LAMBDA: usize = 128;
}
type Fpr = Block;
/// Reverse VOLE Sender.
#[derive(Debug)]
pub struct Sender {
    beta: Vec<Fpr>,
    b: Vec<Fpr>,
    chi: Fpr,
    x: Fpr,
}

/// Reverse VOLE Receiver.
#[derive(Debug)]
pub struct Receiver {
    y: Vec<Fpr>
}
use crate::vole::Rvolesender;
// write_blocks: add this function to Block trait later
use std::io;
pub fn write_blocks <C: AbstractChannel> (channel:& mut C, b: Vec<Block>) -> io::Result<()> {
    (0..b.len()).map(|i| channel.write_block(&b[i]));
    Ok(())
}
pub fn write_pair_blocks <C: AbstractChannel> (channel:& mut C, b: (Block, Block)) -> io::Result<()> {
    channel.write_block(&b.0);
    channel.write_block(&b.1);
    Ok(())
}

pub fn write_pair_vec_blocks <C: AbstractChannel> (channel:& mut C, b: (Vec<Block>, Block)) -> io::Result<()> {
    write_blocks(channel, b.0);
    channel.write_block(&b.1);
    Ok(())
}

pub fn write_pair_pair_vec_blocks<C: AbstractChannel> (channel:& mut C, b: ((Vec<Block>, Block), (Vec<Block>, Block))) 
-> io::Result<()> {
    write_pair_vec_blocks(channel, b.0);
    write_pair_vec_blocks(channel, b.1);
    Ok(())
}
/// implement trait Rvolesender for Sender
impl Rvolesender for Sender{
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>{
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let beta: Vec<Fpr> =(0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let chi = rand::random::<Fpr>();
        let b: Vec<Fpr> =(0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let x = rand::random::<Fpr>();
        Ok(Self{beta, b, chi, x})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<(), Error>{
    let si = ((self.beta, self.chi), (self.b, self.x));
    write_pair_pair_vec_blocks(channel, si);
    Ok(())
    }
}

use crate::vole::Rvolereceiver;
/// implement trait Rvolesender for Receiver
impl Rvolereceiver for Receiver{
fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(& mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>{
        let y = (0..Params::T).map(|_| rand::random::<Fpr>()).collect();
        Ok(Self{y})
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<(), Error>{
        write_blocks(channel, self.y);
        Ok (())
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Block>, Vec<Block>), Error>{
        let beta = channel.read_blocks(Params::T);
        let b = channel.read_blocks(Params::T);
        let chi = channel.read_block().unwrap();
        let x = channel.read_block();
        let gamma = self.y.iter().map(|x| x.clmul(chi).0).collect();
    }

}