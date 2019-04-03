// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use scuttlebutt::Block;

pub struct CuckooHash {
    pub items: Vec<(Option<Block>, Option<usize>, Option<usize>)>,
    hashkeys: Vec<Block>,
    m1: usize,
    m2: usize,
}

pub enum Error {
    InvalidSetSize(usize),
    CuckooHashFull,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidSetSize(s) => write!(f, "invalid set size {}", s),
            Error::CuckooHashFull => write!(f, "cuckoo hash table is full"),
        }
    }
}

const N_ATTEMPTS: usize = 100;
const N_HASHES_1: usize = 3;
const N_HASHES_2: usize = 2;

impl CuckooHash {
    pub fn build(
        inputs: &[Block],
        hashkeys: &[Block],
        m1: usize,
        m2: usize,
    ) -> Result<Self, Error> {
        let mut tbl = CuckooHash::new(hashkeys, m1, m2);
        // Fill table with `inputs`
        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(*input, j)?;
        }
        Ok(tbl)
    }

    pub fn new(hashkeys: &[Block], m1: usize, m2: usize) -> Self {
        let items = vec![(None, None, None); m1 + m2];
        let hashkeys = hashkeys.to_vec();
        Self {
            items,
            m1,
            m2,
            hashkeys,
        }
    }

    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut input = input;
        let mut idx = idx;
        let mut hidx = 0;
        for _ in 0..N_ATTEMPTS {
            let i = super::hash(input, self.hashkeys[hidx], self.m1);
            let old = self.items[i];
            self.items[i] = (Some(input), Some(idx), Some(hidx));
            if let Some(item) = old.0 {
                input = item;
                idx = old.1.unwrap();
                hidx = (old.2.unwrap() + 1) % N_HASHES_1;
            } else {
                return Ok(());
            }
        }
        hidx = 0;
        // Unable to place in bin, so place in extra bins
        for _ in 0..N_ATTEMPTS {
            let i = super::hash(input, self.hashkeys[hidx + N_HASHES_1], self.m2);
            let old = self.items[self.m1 + i];
            self.items[i] = (Some(input), Some(idx), Some(hidx));
            if let Some(item) = old.0 {
                input = item;
                idx = old.1.unwrap();
                hidx = (old.2.unwrap() + 1) % N_HASHES_2;
            } else {
                return Ok(());
            }
        }
        return Err(Error::CuckooHashFull);
    }
}
