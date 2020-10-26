// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! SVOLE utility functions.

use crate::svole::svole_ext::lpn_params::LpnSetupParams;
use rand::Rng;
use rand_core::SeedableRng;
use scuttlebutt::{field::FiniteField, AesRng, Block};

pub fn lpn_mtx_indices<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
) -> [(usize, FE::PrimeField); LpnSetupParams::D] {
    let seed = Block::from(col_idx as u128);
    let mut rng = AesRng::from_seed(seed);
    let mut indices = [(0usize, FE::PrimeField::ONE); LpnSetupParams::D];
    for i in 0..LpnSetupParams::D {
        let mut rand_idx = rng.gen_range(0, rows);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = rng.gen_range(0, rows);
        }
        if FE::PrimeField::MODULUS == 2 {
            indices[i].0 = rand_idx as usize;
        } else {
            let cipher = rng.aes();
            let pt = Block::from(((rand_idx as u128) << 64) ^ col_idx as u128);
            // It is very unlikely that `rand_elt` is zero assuming the prime
            // field is of a large enough modulus!
            let rand_elt: FE::PrimeField =
                FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(cipher.encrypt(pt)));
            indices[i] = (rand_idx as usize, rand_elt);
        }
    }
    indices
}
