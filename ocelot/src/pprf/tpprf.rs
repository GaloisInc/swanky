// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! This is an implementation of the Puncturable Pseudo-Random Function (PPRF) protocol
//! under malicious setting via GGM trees presented in (<https://eprint.iacr.org/2019/1159>, Fig.16 page 26)

use crate::pprf::{errors::Error, Fpr, Fpr2};
use scuttlebutt::{AbstractChannel, Block, Block512, Malicious, AesRng, Channel};

/// tpprf parameters
pub struct Params;
/// intialize the parameters
impl Params {
    pub const LAMBDA: usize = 128;
    pub const ELL: usize = 5;
    pub const PRIME: usize = 7;
    pub const POWR: usize = 2;
    pub const N: usize = 2^Params::ELL;
    }
/// tpprf sender
pub struct Sender{
    x: Fpr
}
type Fprstar = Block;
/// tpprf Receiver 
pub struct Receiver{
    s: Vec<Block>,
    y: Vec<Fprstar>
}