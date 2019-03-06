// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use sha2::{Digest, Sha512};

pub struct PseudorandomCode {}

impl PseudorandomCode {
    pub fn new(_key: Vec<u8>) -> Self {
        Self {}
    }

    pub fn encode(&self, m: &[u8]) -> Vec<u8> {
        let mut h = Sha512::new();
        h.input(m);
        h.result().as_slice().to_vec()
    }
}
