// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Subfield Vector Oblivious Linear-function Evaluation (SVOLE)
//!
//! This module provides implementations of SVOLE Traits.



#![allow(unused_doc_comments)]
use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{CopeeReceiver, CopeeSender, Fp, Fpr, Params, Prf},
};
use ff::*;
use num::pow;
//#[cfg(feature = "derive")]
//pub use ff_derive::*;
use ff::PrimeField;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, Malicious};
use std::marker::PhantomData;
//use scuttlebutt::ff_derive::Fp as PrimeField;
/// A SVOLE Sender.
#[derive(Debug)]
pub struct Sender<OT: OtSender + Malicious> {
    _ot: PhantomData<OT>,
}

/// A SVOLE Receiver.
#[derive(Debug)]
struct Receiver<OT: OtReceiver + Malicious> {
    _ot: PhantomData<OT>,
}
