// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! SVOLE utility functions.

use crate::svole::svole_ext::lpn_params::LpnSetupParams;
use rand::Rng;
use scuttlebutt::{field::FiniteField, AesRng, Block};

pub fn lpn_mtx_indices<FE: FiniteField>(
    _col_idx: usize,
    rows: usize,
    rng: &mut AesRng,
) -> [(usize, FE::PrimeField); LpnSetupParams::D] {
    let mut indices = [(0usize, FE::PrimeField::ONE); LpnSetupParams::D];
    for i in 0..LpnSetupParams::D {
        let mut rand_idx = rng.gen_range(0, rows);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = rng.gen_range(0, rows);
        }
        if FE::PrimeField::MODULUS == 2 {
            indices[i].0 = rand_idx as usize;
        } else {
            let rand_elt: FE::PrimeField =
                FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(rng.gen::<Block>()));
            indices[i] = (rand_idx as usize, rand_elt);
        }
    }
    indices
}
