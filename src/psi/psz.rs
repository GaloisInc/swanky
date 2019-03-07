// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::cuckoo::CuckooHash;
use crate::hashtable::HashTable;
use crate::stream;
use crate::Error;
use ocelot::kkrt::{Output, Seed};
use ocelot::{ObliviousPrfReceiver, ObliviousPrfSender};
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::marker::PhantomData;

pub struct PszPsiSender<OPRF: ObliviousPrfSender> {
    _oprf: PhantomData<OPRF>,
}
pub struct PszPsiReceiver<OPRF: ObliviousPrfReceiver> {
    _oprf: PhantomData<OPRF>,
}

impl<OPRF> PszPsiSender<OPRF>
where
    OPRF: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>,
{
    pub fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let nbins = stream::read_usize(reader)?;
        let binsize = 50; // XXX
        let mut tbl = HashTable::<Block>::new(nbins, binsize);
        for input in inputs.iter() {
            tbl.hash(input);
        }
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let seeds = oprf.send(reader, writer, nbins, rng)?;
        let set = HashSet::new();
        for (i, seed) in seeds.iter().enumerate() {
            for j in 0..binsize {
                set.insert(oprf.compute(seed, &tbl.item(i, j)));
            }
        }
        stream::write_set(writer, set)?;
        Ok(())
    }
}

impl<OPRF> PszPsiReceiver<OPRF>
where
    OPRF: ObliviousPrfReceiver<Input = Block, Output = Output>,
{
    pub fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Vec<[u8; 16]>, Error> {
        let nbins = compute_nbins(inputs.len());
        let stashsize = 0; // XXX FIXME
        stream::write_usize(writer, nbins)?;
        let mut hash = CuckooHash::<Block>::new(nbins, stashsize);
        for input in inputs.iter() {
            hash.hash(input);
        }
        hash.fill(&Default::default());
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let masks = oprf.receive(
            reader,
            writer,
            &hash
                .items
                .iter()
                .map(|item| item.unwrap())
                .collect::<Vec<Block>>(),
            rng,
        )?;
        let set = HashSet::new();
        for mask in masks.iter() {
            set.insert(mask);
        }
        let set_ = stream::read_set(reader)?;
        let result = set.intersection(&set_);
        Ok(result)
    }
}

#[inline]
fn compute_nbins(n: usize) -> usize {
    n // XXX FIXME
}
