// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub struct HashTable<I: Sized + Default + Clone> {
    table: Vec<Vec<I>>,
}

impl<I: Sized + Default + Clone> HashTable<I> {
    #[inline]
    pub fn new(nbins: usize, binsize: usize) -> Self {
        let table = vec![vec![Default::default(); binsize]; nbins];
        Self { table }
    }
    #[inline]
    pub fn hash(&mut self, item: &I) {}
    #[inline]
    pub fn item(&self, bin: usize, idx: usize) -> I {
        self.table[bin][idx]
    }
}
