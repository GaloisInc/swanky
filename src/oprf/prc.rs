// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use arrayref::array_ref;
use scuttlebutt::{Aes128, Block};

pub struct PseudorandomCode {
    cipher1: Aes128,
    cipher2: Aes128,
    cipher3: Aes128,
    cipher4: Aes128,
}

impl PseudorandomCode {
    pub fn new(k1: Block, k2: Block, k3: Block, k4: Block) -> Self {
        let cipher1 = Aes128::new(k1);
        let cipher2 = Aes128::new(k2);
        let cipher3 = Aes128::new(k3);
        let cipher4 = Aes128::new(k4);
        Self {
            cipher1,
            cipher2,
            cipher3,
            cipher4,
        }
    }

    pub fn encode(&self, m: Block) -> [u8; 64] {
        let c1: [u8; 16] = self.cipher1.encrypt(m).into();
        let c2: [u8; 16] = self.cipher2.encrypt(m).into();
        let c3: [u8; 16] = self.cipher3.encrypt(m).into();
        let c4: [u8; 16] = self.cipher4.encrypt(m).into();
        let mut c = c1.to_vec();
        c.append(&mut c2.to_vec());
        c.append(&mut c3.to_vec());
        c.append(&mut c4.to_vec());
        *array_ref![c, 0, 64]
    }
}
