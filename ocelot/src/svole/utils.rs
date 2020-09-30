// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! SVOLE utility functions.

//use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::field::FiniteField;
//use std::iter::FromIterator;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
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

/// Dot product using `FE::multiply_by_prime_subfield`.
pub fn dot_product_with_subfield<FE: FiniteField>(mat: &[FE::PrimeField], x: &[FE]) -> FE {
    x.iter()
        .zip(mat.iter())
        .map(|(&x, &m)| x.multiply_by_prime_subfield(m))
        .sum()
}

/// Code generator that outputs matrix A for the given dimension `k` by `n` that each column of it has uniform `d` non-zero entries.
pub fn code_gen<FE: FiniteField, RNG: CryptoRng + RngCore>(
    rows: usize,
    cols: usize,
    d: usize,
    rng: &mut RNG,
) -> Vec<Vec<FE>> {
    let g = FE::GENERATOR;
    let mut res: Vec<Vec<FE>> = vec![vec![FE::ZERO; rows]; cols];
    for item in res.iter_mut().take(cols) {
        for _j in 0..d {
            let rand_ind: usize = rng.gen_range(0, rows);
            // This goes forever
            /*loop {
                rand_ind = rng.gen_range(0, rows);
                if (res[i])[rand_ind] == FE::ZERO {
                    break;
                }
            }*/
            // This is not the perfect solution to make sure if the rand_ind has not already been chosen.
            let choice = Choice::from(((*item)[rand_ind] == FE::ZERO) as u8);
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
}
