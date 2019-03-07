// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use std::hash::{Hash, Hasher};

pub struct CuckooHash<T> {
    // Contains the bins + stash
    pub(crate) items: Vec<Option<T>>,
    nbins: usize,
}

impl<T: Sized + Hash> CuckooHash<T> {
    pub fn new(nbins: usize, stashsize: usize) -> Self {
        let items = Vec::with_capacity(nbins + stashsize);
        Self { items, nbins }
    }

    pub fn hash<H: Hasher + Default>(&mut self, input: &T) {
        self._hash(input, 3);
    }

    fn _hash<H: Hasher + Default>(&mut self, input: &T, times: usize) {
        if times == 0 {
            // XXX store input in stash
        } else {
            let idx = self._h::<H>(input);
            match self.items[idx] {
                Some(item) => self._hash(&item, times - 1),
                None => (),
            }
            self.items[idx] = Some(*input);
        }
    }

    fn _h<H: Hasher + Default>(&self, input: &T) -> usize {
        let mut hasher = H::default();
        input.hash(&mut hasher);
        (hasher.finish() % self.nbins as u64) as usize
    }

    pub fn fill(&mut self, value: &T) {
        for item in self.items.iter_mut() {
            match item {
                Some(_) => (),
                None => *item = Some(*value),
            }
        }
    }
}
