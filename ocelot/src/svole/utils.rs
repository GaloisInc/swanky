// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! SVOLE utility functions.

//use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::{field::FiniteField, AesRng, Block};
//use std::iter::FromIterator;
use rand::Rng;
use rand_core::SeedableRng;
/// Converts an element of `Fp` to `F(p^r)`.
/// Note that the converted element has the input element as the first component
/// while other components are being `FE::PrimeField::ZERO`.
/*fn to_fpr<FE: FiniteField>(x: FE::PrimeField) -> FE {
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    FE::from_polynomial_coefficients(GenericArray::from_iter((0..r).map(|i| {
        if i == 0 {
            x
        } else {
            FE::PrimeField::ZERO
        }
    })))
}

pub fn to_fpr_vec<FE: FiniteField>(x: &[FE::PrimeField]) -> Vec<FE> {
    x.iter().map(|&x| to_fpr(x)).collect()
}*/

pub fn lpn_mtx_indices<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    if FE::PrimeField::MODULUS == 2 {
        lpn_mtx_indices_bin::<FE>(col_idx, rows, d)
    } else {
        lpn_mtx_indices_fp::<FE>(col_idx, rows, d)
    }
}

/*pub fn lpn_mtx_indices_fp<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let cipher = Aes128::new(seed);
    let mut indices = vec![(0usize, FE::PrimeField::ZERO); d];
    for i in 0..d {
        let mut rand_idx = u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128;
        let mut counter = i;
        while indices.iter().any(|&x| x.0 == rand_idx as usize)  {
            counter += d;
            rand_idx = u128::from(cipher.encrypt(Block::from((counter) as u128))) % rows as u128;
        }
        let exp =
            u128::from(cipher.encrypt(Block::from(rand_idx))) % FE::MULTIPLICATIVE_GROUP_ORDER;
        let nz_elt = FE::PrimeField::GENERATOR;
        nz_elt.pow(exp);
        indices[i] = (rand_idx as usize, nz_elt);
    }
    indices
}*/

pub fn lpn_mtx_indices_fp<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let mut rng = AesRng::from_seed(seed);
    let mut indices = vec![(0usize, FE::PrimeField::ZERO); d];
    for i in 0..d {
        let mut rand_idx = rng.gen_range(0, rows);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = rng.gen_range(0, rows);
        }
        let mut seed2 = rand_idx as u128;
        seed2 <<= 64;
        seed2 ^= col_idx as u128;
        let mut rng2 = AesRng::from_seed(Block::from(seed2));
        let mut rand_elt: FE::PrimeField = FE::PrimeField::random(&mut rng2);
        while rand_elt == FE::PrimeField::ZERO {
            rand_elt = FE::PrimeField::random(&mut rng2);
        }
        indices[i] = (rand_idx as usize, rand_elt);
    }
    //println!("indices in fp = {:?}", indices);
    indices
}

/*
pub fn lpn_mtx_indices_bin<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let cipher = Aes128::new(seed);
    let mut indices = vec![(0usize, FE::PrimeField::ONE); d];
    //let mut counter = 0;
    //let mut rng = AesRng::from_seed(seed);
    //let ds: Vec<u128> = (0..d).map(|i| u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128).collect();
    for i in 0..d {
        let mut rand_idx = (u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128) as usize; //rng.gen_range(0, rows);
        let mut counter = i;
        // Without replacement is expensive
         while indices.iter().any(|&x| x.0 == rand_idx)  {
            counter += d;
            rand_idx = (u128::from(cipher.encrypt(Block::from((counter) as u128))) % rows as u128) as usize;
        }
        indices[i].0 = rand_idx;
        // sum += u[rand_idx as usize];
    }
    indices
}*/

pub fn lpn_mtx_indices_bin<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let mut indices = vec![(0usize, FE::PrimeField::ONE); d];
    let mut rng = AesRng::from_seed(seed);
    for i in 0..d {
        let mut rand_idx = rng.gen_range(0, rows);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = rng.gen_range(0, rows);
        }
        indices[i].0 = rand_idx;
    }
    //println!("indices in bin={:?}", indices);
    indices
}
