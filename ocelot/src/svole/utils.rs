// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::field::FiniteField;
use std::iter::FromIterator;

/// Converts an element of `Fp` to `F(p^r)`.
/// Note that the converted element has the input element as the first component
/// while other components are being `FE::PrimeField::ZERO`.
pub(crate) fn to_fpr<FE: FiniteField>(x: FE::PrimeField) -> FE {
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    FE::from_polynomial_coefficients(GenericArray::from_iter((0..r).map(|i| {
        if i == 0 {
            x
        } else {
            FE::PrimeField::ZERO
        }
    })))
}
