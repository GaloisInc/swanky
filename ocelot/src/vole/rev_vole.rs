// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of reverse VOLE functionality presented in 
//! (<https://eprint.iacr.org/2019/1159>, Fig.14 page 25)
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, AesRng};
use crate::{
    errors::Error,
    vole::{Fpr, Fp},
};
    
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
    gamma: Vec<Fpr>,
    c: Vec<Fpr>
}
use crate::vole::Rvolesender;
// write_blocks: add this function to Block trait later
use std::io;
pub fn write_blocks <C: AbstractChannel> (channel:& mut C, b: Vec<Block>) -> io::Result<()> {
    for i in 0..b.len(){
        channel.write_block(&b[i])?;
    }
    Ok(())
}
pub fn write_pair_blocks <C: AbstractChannel> (channel:& mut C, b: (Block, Block)) -> io::Result<()> {
    channel.write_block(&b.0)?;
    channel.write_block(&b.1)?;
    Ok(())
}

pub fn write_pair_vec_blocks <C: AbstractChannel> (channel:& mut C, b: (Vec<Block>, Block)) -> io::Result<()> {
    write_blocks(channel, b.0)?;
    channel.write_block(&b.1)?;
    Ok(())
}

pub fn write_pair_pair_vec_blocks<C: AbstractChannel> (channel:& mut C, b: ((Vec<Block>, Block), (Vec<Block>, Block))) 
-> io::Result<()> {
    write_pair_vec_blocks(channel, b.0)?;
    write_pair_vec_blocks(channel, b.1)?;
    Ok(())
}
/// implement trait Rvolesender for Sender
impl Rvolesender for Sender{
    fn init() -> Result<Self, Error>{
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let beta: Vec<Fpr> =(0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let chi = rand::random::<Fpr>();
        let b: Vec<Fpr> =(0..Params::T).map(|_| rng.gen::<Fpr>()).collect();
        let x = rand::random::<Fpr>();
        Ok(Self{beta, b, chi, x})
    }

    fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C
    ) -> Result<(), Error>{
    let beta = self.beta.clone();
    let b = self.b.clone();
    let si = ((beta, self.chi), (b, self.x));
    write_pair_pair_vec_blocks(channel, si)?;
    Ok(())
    }
}

use crate::vole::Rvolereceiver;
/// implement trait Rvolesender for Receiver
impl Rvolereceiver for Receiver{
fn init<C: AbstractChannel>(& mut self,
        channel: &mut C
    ) -> Result<Self, Error>{
        let gamma:Vec<Fpr> =Vec::with_capacity(Params::T);
        let c:Vec<Fpr> =Vec::with_capacity(Params::T);
        // (0..Params::T).map(|_| rand::random::<Fpr>()).collect();
        assert_eq!(gamma.len(), Params::T);
        assert_eq!(c.len(), Params::T);
        //let _y = y.clone();
        //write_blocks(channel, _y)?;
        Ok(Self{gamma, c})
    }

    fn receive<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &Vec<Fp>
    ) -> Result<(Vec<Block>, Vec<Block>), Error>{
        assert_eq!(input.len(), Params::T);
        let beta = channel.read_blocks(Params::T)?;
        let b = channel.read_blocks(Params::T)?;
        let chi = channel.read_block()?;
        let x = channel.read_block()?;
        //let y = self.y.clone();
        let ychi:Vec<Block> = input.into_iter().map(|&y| (y.clmul(chi)).0).collect();
        let yx:Vec<Block> = input.iter().map(|&y| y.clmul(x).0).collect();
        let gamma = (0..Params::T).map(|i| sub_blocks(ychi[i], beta[i])).collect();
        let c = (0..Params::T).map(|i| sub_blocks(yx[i], b[i])).collect();
        Ok((gamma, c))
    }

}

pub fn add_blocks (x:Block, y:Block) -> Block{
    let res = Block(unsafe {_mm_add_epi64(x.0, y.0)});
    res
}

pub fn sub_blocks (x:Block, y:Block) -> Block{
    let res = Block(unsafe {_mm_sub_epi64(x.0, y.0)});
    res
}
