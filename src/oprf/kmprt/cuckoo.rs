// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use scuttlebutt::Block;

pub struct CuckooHash {
    pub items: Vec<(Option<Block>, Option<usize>, Option<usize>)>,
    hashkeys: Vec<Block>,
    ms: (usize, usize),
    hs: (usize, usize),
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

impl CuckooHash {
    pub fn build(
        inputs: &[Block],
        hashkeys: &[Block],
        ms: (usize, usize),
        hs: (usize, usize),
    ) -> Result<Self, Error> {
        let mut tbl = CuckooHash::new(hashkeys, ms, hs);
        // Fill table with `inputs`
        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(*input, j)?;
        }
        Ok(tbl)
    }

    fn new(hashkeys: &[Block], ms: (usize, usize), hs: (usize, usize)) -> Self {
        let items = vec![(None, None, None); ms.0 + ms.1];
        let hashkeys = hashkeys.to_vec();
        Self {
            items,
            hashkeys,
            ms,
            hs,
        }
    }

    #[inline]
    fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut input = input;
        let mut idx = idx;
        let mut hidx = 0;
        // Try to place in the first `m1` bins.
        for _ in 0..N_ATTEMPTS {
            let i = super::hash(input, self.hashkeys[hidx], self.ms.0);
            let old = self.items[i];
            self.items[i] = (Some(input), Some(idx), Some(hidx));
            if let Some(item) = old.0 {
                input = item;
                idx = old.1.unwrap();
                hidx = (old.2.unwrap() + 1) % self.hs.0;
            } else {
                return Ok(());
            }
        }
        // Unable to place, so try to place in extra `m2` bins.
        hidx = 0;
        for _ in 0..N_ATTEMPTS {
            let i = super::hash(input, self.hashkeys[hidx + self.hs.0], self.ms.0);
            let old = self.items[self.ms.0 + i];
            self.items[i] = (Some(input), Some(idx), Some(hidx));
            if let Some(item) = old.0 {
                input = item;
                idx = old.1.unwrap();
                hidx = (old.2.unwrap() + 1) % self.hs.1;
            } else {
                return Ok(());
            }
        }
        Err(Error::CuckooHashFull)
    }
}
