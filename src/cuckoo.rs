// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use arrayref::array_ref;
use scuttlebutt::{Aes128, Block};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub(crate) struct CuckooItem {
    // The actual value.
    pub(crate) entry: Block,
    // The input index associated with the entry.
    pub(crate) input_index: usize,
    // The hash index used. None for stash items.
    pub(crate) hash_index: Option<usize>,
}

pub(crate) struct CuckooHash {
    items: Vec<Option<CuckooItem>>,
    pub(crate) nbins: usize,
    pub(crate) stashsize: usize,
    pub(crate) nhashes: usize,
}

/// The number of times to loop when trying to place an entry in a bin.
const NITERS: usize = 1000;

#[inline]
fn compute_nbins(n: usize, nhashes: usize) -> Result<usize, Error> {
    // Numbers taken from <https://thomaschneider.de/papers/PSZ18.pdf>, §3.2.2.
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
    } else if nhashes == 2 {
        // Numbers taken from <https://thomaschneider.de/papers/PSZ18.pdf>,
        // Table 5.
        if n <= 1 << 8 {
            Ok(12)
        } else if n <= 1 << 12 {
            Ok(6)
        } else if n <= 1 << 16 {
            Ok(4)
        } else if n <= 1 << 20 {
            Ok(3)
        } else if n <= 1 << 24 {
            Ok(2)
        } else {
            Err(Error::InvalidCuckooSetSize(n))
        }
    } else {
        // No stash necessary when `nhashes > 2`.
        Ok(0)
    }
}

#[inline]
pub fn compute_masksize(n: usize) -> Result<usize, Error> {
    // Numbers taken from <https://eprint.iacr.org/2016/799>, Table 2 (the `v`
    // column).
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
        let nbins = compute_nbins(inputs.len(), nhashes)?;
        let stashsize = compute_stashsize(inputs.len(), nhashes)?;

        let mut tbl = CuckooHash {
            items: vec![None; nbins + stashsize],
            nbins,
            stashsize,
            nhashes,
        };

        // Fill table with `inputs`.
        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(*input, j)?;
        }

        Ok(tbl)
    }

    /// Place `input`, alongside the input index `idx` it corresponds to, in the
    /// hash table.
    #[inline]
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
                // If there is an item already in the bin, keep iterating,
                // trying to place the new item.
                item = x;
                // Bump the hash index.
                item.hash_index.iter_mut().for_each(|h| {
                    *h += 1;
                    *h %= self.nhashes;
                });
            } else {
                return Ok(());
            }
        }

        // Unable to place in bin, so place in stash. A hash index of `None`
        // indicates stash placement.
        item.hash_index = None;
        for i in self.nbins..self.nbins + self.stashsize {
            if self.items[i].is_none() {
                self.items[i] = Some(item);
                return Ok(());
            }
        }

        // We overflowed the stash, so report an error.
        return Err(Error::CuckooStashOverflow);
    }

    /// Output the bin number for a given hash output `hash` and hash index `hidx`.
    #[inline]
    pub fn bin(hash: Block, hidx: usize, nbins: usize) -> usize {
        // The first 15 bytes are uniformly(-ish) random, so we use the hash
        // directly to determine our bin by indexing the `hidx`th 32 bits of
        // `hash` modulo `nbins`. We can't do this for more than three hash
        // functions though, as the last byte is *not* uniformly(-ish) random.
        // Instead, we run it through AES (slow!).
        if hidx < 3 {
            let bytes: [u8; 16] = hash.into();
            let value = u32::from_le_bytes(*array_ref![bytes[4 * hidx..4 * (hidx + 1)], 0, 4]);
            (value as usize) % nbins
        } else {
            // XXX: This is fine, right?!
            let aes = Aes128::new(hash);
            let h = aes.encrypt(Block::from(hidx as u128));
            (u128::from(h) % (nbins as u128)) as usize
        }
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
