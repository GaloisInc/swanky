// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang SpsVole protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        copee::to_fpr,
        svole_ext::{EqSender, EqReceiver},
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_core::RngCore;
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    AesRng,
    Block,
    Malicious,
    commitment::{Commitment, ShaCommitment}
};
use std::{
    marker::PhantomData,
    ops::{MulAssign, SubAssign},
};

/// Eq Sender.
#[derive(Clone)]
pub struct Sender<FE:FF>{
    _fe: PhantomData<FE>
}

impl <FE:FF> EqSender for Sender<FE>{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>{
        Ok(Self {_fe: PhantomData::<FE>})
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<bool, Error>{
        let va = FE::random(&mut rng);
        channel.write_fe(va)?;
        channel.flush()?;
        let vb = channel.read_fe()?;
        match vb {
            Ok(x) => channel.write_fe(va == x)?,
            Err(e) => return Error::Other("EqSender aborting")
        }

    }    
} 

/// Eq Receiver.
#[derive(Clone)]
pub struct Receiver<FE:FF> {
    _fe: PhantomData<FE>
}

impl <FE:FF> EqReceiver for Receiver<FE>{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>{
        Ok(Self {
            _fe: PhantomData::<FE>
        })
    }
    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<bool, Error>{
        let vb = FE::random(&mut rng);
        let seed = rng.gen::<[u8;32]>();
        let commit = ShaCommitment::new(seed);
        commit.input(vb.to_bytes());
        let result = commit.finish();
        channel.write_bytes(result.to_le_bytes());
        let va = channel.read_fe()?;
        if va != vb {
            Error::Other("EqReceiver aborts")
        }
        else {
            channel.write_bytes(seed)?;
            channel.write_fe(vb)?;
            Ok(va == vb)
        }
    }    
}