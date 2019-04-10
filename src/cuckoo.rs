// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use arrayref::array_ref;
use scuttlebutt::Block;
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub(crate) struct CuckooItem {
    pub(crate) entry: Block,              // the actual value
    pub(crate) input_index: usize,        // the input index associated with the entry
    pub(crate) hash_index: Option<usize>, // the hash index used. None for stash items.
}

pub(crate) struct CuckooHash {
    items: Vec<Option<CuckooItem>>,
    pub(crate) nbins: usize,
    pub(crate) stashsize: usize,
    pub(crate) nhashes: usize,
}

/// The number of times to loop when trying to place an entry in a bin.
const NITERS: usize = 100;

#[inline]
fn compute_nbins(n: usize, nhashes: usize) -> Result<usize, Error> {
    if nhashes == 2 {
        Ok((2.4 * (n as f64)).ceil() as usize)
    } else if nhashes == 3 {
        Ok((1.27 * (n as f64)).ceil() as usize)
    } else if nhashes == 4 {
        Ok((1.09 * (n as f64)).ceil() as usize)
    } else if nhashes == 5 {
        Ok((1.05 * (n as f64)).ceil() as usize)
    } else {
        Err(Error::InvalidCuckooParameters { nitems: n, nhashes })
    }
}

#[inline]
fn compute_stashsize(n: usize, nhashes: usize) -> Result<usize, Error> {
    if nhashes == 1 {
        Err(Error::InvalidCuckooParameters { nitems: n, nhashes })
    } else if nhashes > 2 {
        // No stash necessary when H > 2
        Ok(0)
    } else {
        // nhashes == 2
        if n <= 1 << 8 {
            Ok(8)
        } else if n <= 1 << 12 {
            Ok(5)
        } else if n <= 1 << 16 {
            Ok(3)
        } else if n <= 1 << 28 {
            Ok(2)
        } else if n <= 1 << 32 {
            Ok(4)
        } else {
            Err(Error::InvalidCuckooSetSize(n))
        }
    }
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
        return Err(Error::InvalidCuckooSetSize(n));
    };
    Ok(masksize)
}

impl CuckooHash {
    pub fn new(inputs: &[Block], nhashes: usize) -> Result<CuckooHash, Error> {
        // We don't support more than 2**32 bins due to the way we compute the
        // bin number (cf. the `bin` function below).
        let nbins = compute_nbins(inputs.len(), nhashes)?;
        let stashsize = compute_stashsize(inputs.len(), nhashes)?;

        let mut tbl = CuckooHash {
            items: vec![None; nbins + stashsize],
            nbins,
            stashsize,
            nhashes,
        };

        // Fill table with `inputs`
        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(*input, j)?;
        }

        Ok(tbl)
    }

    /// Place `input`, alongside the input index `idx` it corresponds to, in the
    /// hash table.
    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut item = CuckooItem {
            entry: input,
            input_index: idx,
            hash_index: Some(0),
        };

        for _ in 0..NITERS {
            let i = CuckooHash::bin(item.entry, item.hash_index.unwrap(), self.nbins);

            let opt_item = self.items[i].replace(item);

            if let Some(x) = opt_item {
                // if there is a value already in the bin, continue
                item = x;
                // bump the hash index
                item.hash_index.iter_mut().for_each(|h| {
                    *h += 1;
                    *h %= self.nhashes;
                });
            } else {
                // otherwise, halt
                return Ok(());
            }
        }

        // Unable to place in bin, so place in stash
        // set hash index to none, indicating stash placement
        item.hash_index = None;
        for i in self.nbins..self.nbins + self.stashsize {
            if self.items[i].is_none() {
                self.items[i] = Some(item);
                return Ok(());
            }
        }

        // overflowed the stash
        return Err(Error::CuckooStashOverflow);
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
    pub fn items(&self) -> impl Iterator<Item = &Option<CuckooItem>> {
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
            .map(|_| Block::from(rand::random::<u128>()))
            .collect::<Vec<Block>>();
        let tbl = CuckooHash::new(&inputs, 3);
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
        b.iter(|| CuckooHash::new(&inputs, 3));
    }

    #[bench]
    fn bench_bin(b: &mut Bencher) {
        let input = rand::random::<Block>();
        let hidx = rand::random::<usize>() % 4;
        let range = 53;
        b.iter(|| CuckooHash::bin(input, hidx, range));
    }
}
