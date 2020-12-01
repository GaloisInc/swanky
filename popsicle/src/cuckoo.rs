// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use scuttlebutt::{Aes128, Block};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub(crate) struct CuckooItem {
    // The actual value.
    pub(crate) entry: Block,
    // The input index associated with the entry.
    pub(crate) input_index: usize,
    // The hash index used. None for stash items.
    pub(crate) hash_index: usize,
}

#[derive(Clone)]
pub struct CuckooHashLarge{
    pub(crate) items: Vec<CuckooHash>,
    pub nbins: usize, // total number of bins
    pub nmegabins: usize,
    pub megasize: usize,
    pub nhashes: usize,
}

#[derive(Clone)]
pub(crate) struct CuckooHash{
    pub(crate) items: Vec<Option<CuckooItem>>,
    pub(crate) nbins: usize,
    pub(crate) nhashes: usize,
}

/// The number of times to loop when trying to place an entry in a bin.
const NITERS: usize = 1000;

fn compute_nbins(n: usize, nhashes: usize) -> Result<usize, Error> {
    // Numbers taken from <https://thomaschneider.de/papers/PSZ18.pdf>, §3.2.2.
    if nhashes == 3 {
        if n < 1 << 27 {
            Ok((1.27 * (n as f64)).ceil() as usize) // good up to set size 2^26
        } else {
            Ok((1.62 * (n as f64)).ceil() as usize) // required for 2^27
        }
    } else if nhashes == 4 {
        Ok((1.09 * (n as f64)).ceil() as usize)
    } else if nhashes == 5 {
        Ok((1.05 * (n as f64)).ceil() as usize)
    } else {
        Err(Error::InvalidCuckooParameters { nitems: n, nhashes })
    }
}

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
    } else if n <= 1 << 28 {
        12
    } else {
        return Err(Error::InvalidCuckooSetSize(n));
    };
    Ok(masksize)
}

impl CuckooHash {
    /// Build a new cuckoo hash table, hashing `inputs` in. We require that the
    /// lower-order-bits of the values in `inputs` are zero-ed out, as those
    /// bits will be used to store the hash index.
    pub fn new(inputs: &[Block], nhashes: usize) -> Result<CuckooHash, Error> {
        let nbins = compute_nbins(inputs.len(), nhashes)?;

        let mut tbl = CuckooHash {
            items: vec![None; nbins],
            nbins,
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
    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut item = CuckooItem {
            entry: input,
            input_index: idx,
            hash_index: 0,
        };
        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00);

        for _ in 0..NITERS{
            item.entry &= mask;
            let i = CuckooHash::bin(item.entry, item.hash_index, self.nbins);
            item.entry ^= Block::from(item.hash_index as u128);
            let opt_item = self.items[i].replace(item);
            if let Some(x) = opt_item {
                // If there is an item already in the bin, keep iterating,
                // trying to place the new item.
                item = x;
                // Bump the hash index.
                item.hash_index = (item.hash_index + 1) % self.nhashes;
            } else {
                return Ok(());
            }
        }
        Err(Error::CuckooHashFull)
    }

    /// Output the bin number for a given hash output `hash` and hash index `hidx`.
    pub fn bin(hash: Block, hidx: usize, nbins: usize) -> usize {
        // The first 15 bytes of `hash` are uniformly(-ish) random, so we use it
        // directly to determine our bin by indexing the `hidx`th 32 bits of
        // `hash` then mod-ing it by `nbins`. We can't do this for more than
        // three hash functions though, as the last byte is *not*
        // uniformly(-ish) random. Instead, we run it through AES (slow!).
        if hidx < 3 {
            let mut array = [0u8; 4];
            let bytes: [u8; 16] = hash.into();
            array.copy_from_slice(&bytes[4 * hidx..4 * (hidx + 1)]);
            let value = u32::from_le_bytes(array);
            (value as usize) % nbins
        } else {
            // In this case, compute `AES_{hash}(hidx)`.
            let aes = Aes128::new(hash);
            let h = aes.encrypt(Block::from(hidx as u128));
            (u128::from(h) % (nbins as u128)) as usize
        }
    }
}


impl Debug for CuckooHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for i in 0..self.nbins {
            writeln!(f, "{}: {:?}", i, self.items[i])?;
        }
        Ok(())
    }
}

impl CuckooHashLarge{
    /// Build a new cuckoo hash table, hashing `inputs` in. We require that the
    /// lower-order-bits of the values in `inputs` are zero-ed out, as those
    /// bits will be used to store the hash index.
    pub fn new(inputs: &[Block], nhashes: usize, megasize: usize) -> Result<CuckooHashLarge, Error> {
        let nbins = compute_nbins(inputs.len(), nhashes)?;
        let nmegabins = ((nbins as f64)/(megasize as f64)).ceil() as usize;
        let last_bin = nbins % megasize;

        let mut items: Vec<CuckooHash> = Vec::new();
        for i in 0..nmegabins{
            let mut binsize = megasize;
            if i == (nmegabins - 1) && last_bin != 0{
                binsize = last_bin;
            }
            items.push(
                CuckooHash{
                        items: vec![None; binsize],
                        nbins: binsize,
                        nhashes,
                }
            );
        }


        let mut tbl = CuckooHashLarge {
            items,
            nbins,
            nmegabins,
            megasize,
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
    pub fn hash(&mut self, input: Block, idx: usize) -> Result<(), Error> {
        let mut item = CuckooItem {
            entry: input,
            input_index: idx,
            hash_index: 0,
        };
        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00);

        for _ in 0..NITERS {
            item.entry &= mask;

            let i = CuckooHash::bin(item.entry, item.hash_index, self.nbins);
            let small_i = i % self.megasize;
            let megabin_i =  i / self.megasize;

            item.entry ^= Block::from(item.hash_index as u128);
            let opt_item = self.items[megabin_i].items[small_i].replace(item);
            if let Some(x) = opt_item {
                // If there is an item already in the bin, keep iterating,
                // trying to place the new item.
                item = x;
                // Bump the hash index.
                item.hash_index = (item.hash_index + 1) % self.nhashes;
            } else {
                return Ok(());
            }
        }
        Err(Error::CuckooHashFull)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use itertools::Itertools;
    use rand::Rng;
    use scuttlebutt::AesRng;

    const NHASHES: usize = 3;
    const ITEMSIZE: usize = 8;
    const SETSIZE: usize = 1 << 16;

    #[test]
    fn test_build() {
        let mut rng = AesRng::new();
        let inputs = utils::rand_vec_vec(SETSIZE, ITEMSIZE, &mut rng);
        let key = rng.gen();
        let hashes = utils::compress_and_hash_inputs(&inputs, key);
        let tbl = CuckooHash::new(&hashes, NHASHES);
        assert!(tbl.err().is_none());
    }

    #[test]
    fn hashing() {
        let mut rng = AesRng::new();
        let inputs = utils::rand_vec_vec(SETSIZE, ITEMSIZE, &mut rng);

        let key = rng.gen();
        let hashes = utils::compress_and_hash_inputs(&inputs, key);
        let cuckoo = CuckooHash::new(&hashes, NHASHES).unwrap();

        // map inputs to table using all hash functions
        let mut table = vec![Vec::new(); cuckoo.nbins];

        for &x in &hashes {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(x, h, cuckoo.nbins);
                table[bin].push(x ^ Block::from(h as u128));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j].
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
            }
        }

        // each item in a cuckoo bin should also be in one of the table bins
        for (opt_item, bin) in cuckoo.items.iter().zip_eq(&table) {
            if let Some(item) = opt_item {
                assert!(bin.iter().any(|bin_elem| *bin_elem == item.entry));
            }
        }
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    const SETSIZE: usize = 1 << 16;

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
