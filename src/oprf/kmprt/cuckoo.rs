// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use scuttlebutt::Block;

#[derive(Clone)]
pub struct Item {
    pub entry: Block,
    pub index: usize,
    hindex: usize,
}

pub struct CuckooHash {
    pub items: Vec<Option<Item>>,
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
        let items = vec![None; ms.0 + ms.1];
        let hashkeys = hashkeys.to_vec();
        Self {
            items,
            hashkeys,
            ms,
            hs,
        }
    }

    #[inline]
    fn _hash(
        &mut self,
        entry: Block,
        index: usize,
        h: usize,
        hoffset: usize,
        m: usize,
        moffset: usize,
    ) -> Option<(Block, usize)> {
        let mut entry = entry;
        let mut index = index;
        let mut hindex = 0;
        for _ in 0..N_ATTEMPTS {
            let i = super::hash_input(entry, self.hashkeys[hoffset + hindex], m);
            let new = Item {
                entry,
                index,
                hindex,
            };
            if let Some(item) = &self.items[moffset + i] {
                entry = item.entry;
                index = item.index;
                hindex = (item.hindex + 1) % h;
                self.items[moffset + i] = Some(new);
            } else {
                self.items[moffset + i] = Some(new);
                return None;
            }
        }
        return Some((entry, index));
    }

    #[inline]
    fn hash(&mut self, entry: Block, index: usize) -> Result<(), Error> {
        // Try to place in the first `m₁` bins.
        match self._hash(entry, index, self.hs.0, 0, self.ms.0, 0) {
            None => Ok(()),
            // Unable to place, so try to place in extra `m₂` bins.
            Some((entry, index)) => {
                match self._hash(entry, index, self.hs.1, self.hs.0, self.ms.1, self.ms.0) {
                    None => Ok(()),
                    Some(..) => Err(Error::CuckooHashFull),
                }
            }
        }
    }
}

//
// Benchmarks.
//

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{black_box, Bencher};

    const SET_SIZE: usize = 1 << 12;

    #[bench]
    fn bench_build(b: &mut Bencher) {
        let inputs = black_box(
            (0..SET_SIZE)
                .map(|_| rand::random::<Block>())
                .collect::<Vec<Block>>(),
        );
        let params = super::super::Parameters::new(inputs.len()).unwrap();
        let hashkeys = black_box(
            (0..params.h1 + params.h2)
                .map(|_| rand::random::<Block>())
                .collect::<Vec<Block>>(),
        );
        b.iter(|| {
            CuckooHash::build(
                &inputs,
                &hashkeys,
                (params.m1, params.m2),
                (params.h1, params.h2),
            )
        });
    }
}
