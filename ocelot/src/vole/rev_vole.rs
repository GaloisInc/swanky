// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of reverse VOLE functionality presented in
//! (<https://eprint.iacr.org/2019/1159>, Fig.14 page 25)

#![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{
    errors::Error,
    pprf::pprf::{read_fp, write_fp},
    vole::{Fp, ReceiverDom, SenderDom},
};
use ff::*;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Block512, Malicious};
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
pub struct Sender;

/// Reverse VOLE Receiver.
#[derive(Debug)]
pub struct Receiver;

use crate::vole::Rvolesender;

/// implement trait Rvolesender for Sender
impl Rvolesender for Sender {
    fn send<C: AbstractChannel>(channel: &mut C, input: SenderDom) -> Result<(), Error> {
        let beta = (input.0).0;
        let chi = (input.0).1;
        let b = (input.1).0;
        let x = (input.1).1;
        for i in 0..Params::T {
            write_fp(channel, beta[i])?;
            write_fp(channel, b[i])?;
        }
        write_fp(channel, chi)?;
        write_fp(channel, x)?;
        Ok(())
    }
}

use crate::vole::Rvolereceiver;
/// implement trait Rvolesender for Receiver
impl Rvolereceiver for Receiver {
    fn receive<C: AbstractChannel>(
        channel: &mut C,
        input: ReceiverDom,
    ) -> Result<(Vec<Fp>, Vec<Fp>), Error> {
        assert_eq!(input.len(), Params::T);
        let beta: Vec<Fp> = (0..Params::T).map(|i| read_fp(channel).unwrap()).collect();
        let b: Vec<Fp> = (0..Params::T).map(|i| read_fp(channel).unwrap()).collect();
        let chi = read_fp(channel)?;
        let x = read_fp(channel)?;
        let _input = input.clone();
        let mut ychi: Vec<Fp> = input
            .into_iter()
            .map(|mut y| {
                y.mul_assign(&chi);
                y
            })
            .collect();
        let mut yx: Vec<Fp> = _input
            .into_iter()
            .map(|mut y| {
                y.mul_assign(&x);
                y
            })
            .collect();
        let gamma = (0..Params::T)
            .map(|i| {
                ychi[i].sub_assign(&beta[i]);
                ychi[i]
            })
            .collect();
        let c = (0..Params::T)
            .map(|i| {
                yx[i].sub_assign(&b[i]);
                yx[i]
            })
            .collect();
        Ok((gamma, c))
    }
}
