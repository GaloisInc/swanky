// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use generic_array::typenum::Unsigned;
use scuttlebutt::field::FiniteField;

pub fn gen_pows<FE: FiniteField>() -> Vec<FE> {
    let mut acc = FE::ONE;
    let r = FE::PolynomialFormNumCoefficients::to_usize();
    let mut pows = vec![FE::ZERO; r];
    for item in pows.iter_mut() {
        *item = acc;
        acc *= FE::GENERATOR;
    }
    pows
}
