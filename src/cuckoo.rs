// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use scuttlebutt::{AesHash, Block};
use std::fmt::Debug;

pub struct CuckooHash {
    // Contains the bins + stash
    pub(crate) items: Vec<Option<Block>>,
    nbins: usize,
    stashsize: usize,
    hashes: Vec<AesHash>,
}

impl CuckooHash {
    pub fn new(nbins: usize, stashsize: usize, init_states: Vec<Block>) -> Self {
        let items = vec![None; nbins + stashsize];
        let hashes = init_states.into_iter().map(AesHash::new).collect();
        Self {
            items,
            nbins,
            stashsize,
            hashes,
        }
    }

    pub fn hash(&mut self, input: Block) -> Result<(), Error> {
        self._hash(input, self.hashes.len())
    }

    fn _hash(&mut self, input: Block, times: usize) -> Result<(), Error> {
        if times == 0 {
            // Put `input` in the stash
            for i in self.nbins..self.nbins + self.stashsize {
                if self.items[i].is_none() {
                    self.items[i] = Some(input.clone());
                    return Ok(());
                }
            }
            return Err(Error::CuckooHashFull);
        } else {
            let idx = Self::hash_with_state(input, &self.hashes[times - 1], self.nbins);
            let item = &self.items[idx];
            match item {
                Some(item) => self._hash(item.clone(), times - 1),
                None => Ok(()),
            }?;
            self.items[idx] = Some(input.clone());
        }
        Ok(())
    }

    pub fn hash_with_state(input: Block, hash: &AesHash, range: usize) -> usize {
        let output = hash.cr_hash(0, input);
        let block: u128 = output.into();
        (block % (range as u128)) as usize
    }

    pub fn fill(&mut self, value: Block) {
        for item in self.items.iter_mut() {
            match item {
                Some(_) => (),
                None => *item = Some(value.clone()),
            }
        }
    }
}

impl Debug for CuckooHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for i in 0..self.nbins {
            write!(f, "{}: {:?}\n", i, self.items[i])?;
        }
        for i in self.nbins..self.nbins + self.stashsize {
            write!(f, "[Stash] {}: {:?}\n", i, self.items[i])?;
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
