#![allow(clippy::too_many_arguments)]

use swanky_block::Block;
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher};

#[derive(Clone, Debug)]
pub struct Item {
    pub entry: Block,
    pub index: usize,
    hindex: usize,
}

pub struct CuckooHash {
    pub items: Vec<Option<Item>>,
    ms: (usize, usize),
    hs: (usize, usize),
}

pub enum Error {
    CuckooHashFull,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CuckooHashFull => write!(f, "hash table is full"),
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
        let mut tbl = CuckooHash::new(ms, hs);

        let hashkeys = hashkeys
            .iter()
            .map(|k| Aes128EncryptOnly::new_with_key(*k))
            .collect::<Vec<Aes128EncryptOnly>>();
        // Fill table with `inputs`

        for (j, input) in inputs.iter().enumerate() {
            tbl.hash(&hashkeys, *input, j)?;
        }
        Ok(tbl)
    }

    fn new(ms: (usize, usize), hs: (usize, usize)) -> Self {
        let items = vec![None; ms.0 + ms.1];
        Self { items, ms, hs }
    }

    fn _hash(
        &mut self,
        hashkeys: &[Aes128EncryptOnly],
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
            let i = super::hash_input_keyed(&hashkeys[hoffset + hindex], entry, m);
            let new = Item {
                entry,
                index,
                hindex,
            };
            match &self.items[moffset + i].replace(new) {
                None => {
                    return None;
                }
                Some(item) => {
                    entry = item.entry;
                    index = item.index;
                    hindex = (item.hindex + 1) % h;
                }
            }
        }
        Some((entry, index))
    }

    fn hash(
        &mut self,
        hashkeys: &[Aes128EncryptOnly],
        entry: Block,
        index: usize,
    ) -> Result<(), Error> {
        // Try to place in the first `m₁` bins.
        match self._hash(hashkeys, entry, index, self.hs.0, 0, self.ms.0, 0) {
            None => Ok(()),
            // Unable to place, so try to place in extra `m₂` bins.
            Some((entry, index)) => {
                match self._hash(
                    hashkeys, entry, index, self.hs.1, self.hs.0, self.ms.1, self.ms.0,
                ) {
                    None => Ok(()),
                    Some(..) => Err(Error::CuckooHashFull),
                }
            }
        }
    }
}
