// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::Error;
use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub struct CuckooHash<T> {
    // Contains the bins + stash
    pub(crate) items: Vec<Option<(T, usize)>>,
    nbins: usize,
    stashsize: usize,
    init_states: Vec<u64>,
}

impl<T: Clone + std::fmt::Debug + Hash> CuckooHash<T> {
    pub fn new(nbins: usize, stashsize: usize, init_states: Vec<u64>) -> Self {
        let items = vec![None; nbins + stashsize];
        Self {
            items,
            nbins,
            stashsize,
            init_states,
        }
    }

    pub fn hash<H: Hasher + Default>(&mut self, input: &T) -> Result<(), Error> {
        self._hash::<H>(input, self.init_states.len())
    }

    fn _hash<H: Hasher + Default>(&mut self, input: &T, times: usize) -> Result<(), Error> {
        if times == 0 {
            // Put `input` in the stash
            for i in self.nbins..self.nbins + self.stashsize {
                if self.items[i].is_none() {
                    self.items[i] = Some((input.clone(), 0));
                    return Ok(());
                }
            }
            return Err(Error::CuckooHashFull);
        } else {
            let idx = Self::hash_with_state::<H>(input, self.init_states[times - 1], self.nbins);
            let item = &self.items[idx];
            match item {
                Some(item) => self._hash::<H>(&item.0.clone(), times - 1),
                None => Ok(()),
            }?;
            self.items[idx] = Some((input.clone(), times));
        }
        Ok(())
    }

    pub fn hash_with_state<H: Hasher + Default>(input: &T, state: u64, range: usize) -> usize {
        let mut hasher = H::default();
        state.hash(&mut hasher);
        input.hash(&mut hasher);
        (hasher.finish() % range as u64) as usize
    }

    pub fn fill(&mut self, value: &T) {
        for item in self.items.iter_mut() {
            match item {
                Some(_) => (),
                None => *item = Some((value.clone(), 0)),
            }
        }
    }
}
