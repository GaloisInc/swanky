// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use arrayref::array_ref;
use scuttlebutt::Block;
use std::fmt::Debug;

pub(crate) struct CuckooHash {
    // Contains the bins + stash. Each entry is a tuple containing:
    // 0. The entry, or None if there is no such entry.
    // 1. The input index associated with the entry.
    // 2. The hash index used.
    items: Vec<(Option<Block>, Option<usize>, Option<usize>)>,
    pub(crate) nbins: usize,
    pub(crate) stashsize: usize,
}

/// The number of hash functions to use in the cuckoo hash.
pub(crate) const NHASHES: usize = 2;
/// The number of times to loop when trying to place an entry in a bin.
const NITERS: usize = 100;

#[inline]
fn compute_nbins(n: usize) -> usize {
    (2.4 * (n as f64)).ceil() as usize
}
#[inline]
fn compute_stashsize(n: usize) -> Result<usize, Error> {
    let stashsize = if n <= 1 << 8 {
        8
    } else if n <= 1 << 12 {
        5
    } else if n <= 1 << 16 {
        3
    } else if n <= 1 << 28 {
        2
    } else if n <= 1 << 32 {
        4
    } else {
        return Err(Error::InvalidSetSize(n));
    };
    Ok(stashsize)
}
#[inline]
pub fn compute_masksize(n: usize) -> Result<usize, Error> {
    let masksize = if n <= 1 << 8 {
        7
    } else if n <= 1 << 12 {
        8
    } else if n <= 1 << 16 {
        9
    } else if n <= 1 << 20 {
        10
    } else if n <= 1 << 24 {
        11
    } else {
        return Err(Error::InvalidSetSize(n));
    };
    Ok(masksize)
}

impl CuckooHash {
    pub fn build(inputs: &[Block]) -> Result<Self, Error> {
        let nbins = compute_nbins(inputs.len());
        // We don't support more than 2**32 bins due to the way we compute the
        // bin number (cf. the `bin` function below).
        if nbins >= 1 << 32 {
            return Err(Error::InvalidSetSize(inputs.len()));
        }
        let stashsize = compute_stashsize(inputs.len())?;
        let mut tbl = CuckooHash::new(nbins, stashsize);
        // Fill table with `inputs`
        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(*input, j)?;
        }
        Ok(tbl)
    }

    pub fn new(nbins: usize, stashsize: usize) -> Self {
        let items = vec![(None, None, None); nbins + stashsize];
        Self {
            items,
            nbins,
            stashsize,
        }
    }

    /// Place `input`, alongside the input index `idx` it corresponds to, in the
    /// hash table.
    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut input = input;
        let mut idx = idx;
        let mut hidx = 0;
        for _ in 0..NITERS {
            let i = Self::bin(input, hidx, self.nbins);
            let old = self.items[i];
            self.items[i] = (Some(input), Some(idx), Some(hidx));
            if let Some(item) = old.0 {
                input = item;
                idx = old.1.unwrap();
                hidx = (old.2.unwrap() + 1) % NHASHES;
            } else {
                return Ok(());
            }
        }
        // Unable to place in bin, so place in stash
        for i in self.nbins..self.nbins + self.stashsize {
            if self.items[i].0.is_none() {
                self.items[i] = (Some(input), Some(idx), None);
                return Ok(());
            }
        }
        return Err(Error::CuckooHashFull);
    }

    /// Output the bin number for a given hash output `hash` and hash index `hidx`.
    #[inline]
    pub fn bin(hash: Block, hidx: usize, nbins: usize) -> usize {
        debug_assert!(hidx <= 4);
        let bytes: [u8; 16] = hash.into();
        let value: u32 =
            unsafe { std::mem::transmute(*array_ref![bytes[4 * hidx..4 * (hidx + 1)], 0, 4]) };
        (value as usize) % nbins
    }

    #[inline]
    pub fn items(&self) -> std::slice::Iter<(Option<Block>, Option<usize>, Option<usize>)> {
        self.items.iter()
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

#[cfg(test)]
mod tests {
    use super::*;

    const SETSIZE: usize = 1 << 16;

    #[test]
    fn test_build() {
        let inputs = (0..SETSIZE)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        let tbl = CuckooHash::build(&inputs);
        assert!(tbl.err().is_none());
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    const SETSIZE: usize = 1 << 12;

    #[bench]
    fn bench_build(b: &mut Bencher) {
        let inputs = (0..SETSIZE)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        b.iter(|| CuckooHash::build(&inputs));
    }

    #[bench]
    fn bench_bin(b: &mut Bencher) {
        let input = rand::random::<Block>();
        let hidx = rand::random::<usize>() % 4;
        let range = 53;
        b.iter(|| CuckooHash::bin(input, hidx, range));
    }
}
