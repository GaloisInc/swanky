// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use scuttlebutt::{AesHash, Block};
use std::fmt::Debug;

const NITERS: usize = 100;

pub(crate) struct CuckooHash {
    // Contains the bins + stash
    pub(crate) items: Vec<(Option<Block>, usize, usize)>,
    nbins: usize,
    stashsize: usize,
    hashes: Vec<AesHash>,
}

impl CuckooHash {
    pub fn new(nbins: usize, stashsize: usize, init_states: &[Block]) -> Self {
        let items = vec![(None, usize::max_value(), usize::max_value()); nbins + stashsize];
        let hashes = init_states.iter().map(|s| AesHash::new(*s)).collect();
        Self {
            items,
            nbins,
            stashsize,
            hashes,
        }
    }

    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        self._hash(input, idx, NITERS)
    }

    pub fn _hash(&mut self, input: Block, idx: usize, times: usize) -> Result<(), Error> {
        if times == 0 {
            // Put `input` in the stash, or fail if the stash is full.
            for i in self.nbins..self.nbins + self.stashsize {
                if self.items[i].0.is_none() {
                    self.items[i] = (Some(input), idx, usize::max_value());
                    return Ok(());
                }
            }
            return Err(Error::CuckooHashFull);
        }
        let indices = self
            .hashes
            .iter()
            .map(|hash| Self::hash_with_state(input, hash, self.nbins))
            .collect::<Vec<usize>>();
        for (i, j) in indices.iter().enumerate() {
            let item = &self.items[*j].0;
            match item {
                Some(_) => (),
                None => {
                    self.items[*j] = (Some(input), idx, i);
                    return Ok(());
                }
            };
        }
        // Item doesn't fit, so evict an item at random.
        let hidx = rand::random::<usize>() % self.hashes.len();
        let idx_ = indices[hidx];
        let evicted = self.items[idx_];
        self.items[idx_] = (Some(input), idx, hidx);
        self._hash(evicted.0.unwrap(), evicted.1, times - 1)?;
        Ok(())
    }

    pub fn hash_with_state(input: Block, hash: &AesHash, range: usize) -> usize {
        let output = hash.cr_hash(0, input);
        (u128::from(output) % (range as u128)) as usize
    }

    pub fn fill(&mut self, value: Block) {
        for item in self.items.iter_mut() {
            match item.0 {
                Some(_) => (),
                None => *item = (Some(value), usize::max_value(), usize::max_value()),
            }
        }
    }
}

impl Debug for CuckooHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for i in 0..self.nbins {
            writeln!(f, "{}: {:?}", i, self.items[i])?;
        }
        for i in self.nbins..self.nbins + self.stashsize {
            writeln!(f, "[Stash] {}: {:?}", i, self.items[i])?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_hash_with_state(b: &mut Bencher) {
        let input = rand::random::<Block>();
        let hash = AesHash::new(rand::random::<Block>());
        let range = 53;
        b.iter(|| CuckooHash::hash_with_state(input, &hash, range));
    }
}
