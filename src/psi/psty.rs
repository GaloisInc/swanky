// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Tkachenko-Yanai private set intersection
//! protocol (cf. <https://eprint.iacr.org/2019/241>).

// use crate::cuckoo::{compute_masksize, CuckooHash};
// use crate::stream;
use crate::Error;
use crate::{Receiver as PsiReceiver, Sender as PsiSender};
// use ocelot::oprf::kkrt::Output;
// use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
// use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
// use scuttlebutt::utils as scutils;
use scuttlebutt::{SemiHonest};
// use sha2::{Digest, Sha256};
// use std::collections::HashSet;
use std::io::{Read, Write};

const NHASHES: usize = 3;

/// Private set intersection sender.
pub struct Sender { }

/// Private set intersection receiver.
pub struct Receiver { }

impl PsiSender for Sender {
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        unimplemented!()
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl PsiReceiver for Receiver {
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        unimplemented!()
    }

    fn receive<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        unimplemented!()
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert!(true);
    }
}
