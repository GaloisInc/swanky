// TODO:
//
// (1) Use ocelot's cuckoo hash (ch) instead of popsicle's: popsicle's current ch has a bug where
//     it is always full and fails for certain numbers like 100,000 and larger powers of 10.
// (2) Once (1) is complete, revert handling megabins after the ch is done instead of during (and
//     effectively get rid of the ch large structure and methods currently in popsicle/src/cuckoo)
//     the current megabin handling is an artifact of older bugs that stalled the system for large sets

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

impl CuckooItem {
    #[cfg(any(feature = "psty", feature = "psty_payload"))]
    /// Replace the first byte of the entry with the hash index. Used in PSTY.
    pub fn entry_with_hindex(&self) -> Block {
        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00);
        (self.entry & mask) ^ Block::from(self.hash_index as u128)
    }
}

pub(crate) struct CuckooHash {
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
        for _ in 0..NITERS {
            let i = CuckooHash::bin(item.entry, item.hash_index, self.nbins);
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
        let aes = Aes128::new(hash);
        let h = aes.encrypt(Block::from(hidx as u128));
        (u128::from(h) % (nbins as u128)) as usize
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use itertools::Itertools;
    use rand::Rng;
    use scuttlebutt::AesRng;

    const NHASHES: usize = 3;
    const ITEMSIZE: usize = 8;
    const SETSIZE: usize = 10000;

    #[test]
    fn test_build() {
        let mut rng = AesRng::new();
        let inputs = utils::rand_vec_vec(SETSIZE, ITEMSIZE, &mut rng);
        let key = rng.gen();
        let hashes = utils::compress_and_hash_inputs(&inputs, key);
        let _ = CuckooHash::new(&hashes, NHASHES).unwrap();
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
                table[bin].push(x);
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
