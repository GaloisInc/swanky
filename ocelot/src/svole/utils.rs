// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! SVOLE utility functions.

//use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::{field::FiniteField, Aes128, AesRng, Block};
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
use subtle::Choice; //ConditionallySelectable;
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

pub fn lpn_mtx_indices_fp<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let cipher = Aes128::new(seed);
    let mut indices = vec![(0usize, FE::PrimeField::ZERO); d];
    for i in 0..d {
        let rand_idx = u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128;
        let exp =
            u128::from(cipher.encrypt(Block::from(rand_idx))) % FE::MULTIPLICATIVE_GROUP_ORDER;
        let nz_elt = FE::PrimeField::GENERATOR;
        nz_elt.pow(exp);
        indices[i] = (rand_idx as usize, nz_elt);
        // sum += u[rand_idx as usize].multiply_by_prime_subfield(nz_elt);
    }
    indices
}

pub fn lpn_mtx_indices_bin<FE: FiniteField>(
    col_idx: usize,
    rows: usize,
    d: usize,
) -> Vec<(usize, FE::PrimeField)> {
    let seed = Block::from(col_idx as u128);
    let cipher = Aes128::new(seed);
    let mut indices = vec![(0usize, FE::PrimeField::ONE); d];
    //let mut rng = AesRng::from_seed(seed);
    //let ds: Vec<u128> = (0..d).map(|i| u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128).collect();
    for i in 0..d {
        let rand_idx = (u128::from(cipher.encrypt(Block::from(i as u128))) % rows as u128) as usize; //rng.gen_range(0, rows);

        // Without replacement is expensive
        /* loop {
                if ds.iter().any(|&x| x != rand_idx) {
                    ds.push(rand_idx);
                    sum += u[rand_idx as usize];
                    break;
                }
                rand_idx = u128::from(cipher.encrypt(Block::from((i + d + 1) as u128))) % rows as u128;
        }*/
        indices[i].0 = rand_idx;
        // sum += u[rand_idx as usize];
    }
    indices
}

//Code generator that outputs matrix A for the given dimension `k` by `n` that each column of it has uniform `d` non-zero entries.
/*pub fn code_gen<FE: FiniteField, RNG: CryptoRng + RngCore>(
    rows: usize,
    cols: usize,
    d: usize,
    rng: &mut RNG,
) -> Vec<Vec<FE>> {
    let g = FE::GENERATOR;
    let mut res: Vec<Vec<FE>> = vec![vec![FE::ZERO; rows]; cols];
    for item in res.iter_mut().take(cols) {
        for _j in 0..d {
            let rand_ind: usize = rng.gen_range(0, rows);*/
// This goes forever
/*loop {
    rand_ind = rng.gen_range(0, rows);
    if (res[i])[rand_ind] == FE::ZERO {
        break;
    }
}*/
// This is not the perfect solution to make sure if the rand_ind has not already been chosen.
/*let choice = Choice::from(((*item)[rand_ind] == FE::ZERO) as u8);
            let index = u128::conditional_select(
                &(rng.gen_range(0, rows) as u128),
                &(rand_ind as u128),
                choice,
            );
            let nz_elt = g;
            let fe = nz_elt.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
            (*item)[index as usize] = fe;
        }
    }
    res
}*/

/*pub fn access_cell<FE: FiniteField>(
    col_idx: usize,
    row_idx: usize,
    rows: usize,
    d: usize,
) -> FE::PrimeField {
    let seed = Block::from(col_idx as u128);
    let mut rng = AesRng::from_seed(seed);
    let mut ds = vec![0; 10];
    for _j in 0..d {
        let mut rand_idx: usize = rng.gen_range(0, rows);
        loop {
            if ds.iter().any(|&x| x != rand_idx) {
                ds.push(rand_idx);
                break;
            }
            rand_idx = rng.gen_range(0, rows);
        }
    }
    let mut seed2 = row_idx as u128;
    seed2 <<= 64;
    seed2 ^= col_idx as u128;
    let mut rng2 = AesRng::from_seed(Block::from(seed2));
    if ds.iter().any(|&x| x == row_idx) {
        let nz_elt = FE::PrimeField::GENERATOR;
        nz_elt.pow(rng2.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        nz_elt
    } else {
        FE::PrimeField::ZERO
    }
}*/
