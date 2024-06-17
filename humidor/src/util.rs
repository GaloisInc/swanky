//! Utility functions for Ligero

use ndarray::{Array1, ArrayView1};

use scuttlebutt::field::FiniteField;
#[cfg(test)]
use scuttlebutt::ring::FiniteRing;

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
pub type TestField = scuttlebutt::field::F2e19x3e26;
#[cfg(test)]
pub type TestHash = sha2::Sha256;

#[cfg(test)]
pub fn arb_test_field() -> BoxedStrategy<TestField> {
    any::<u128>()
        .prop_map(|seed| TestField::from_uniform_bytes(&seed.to_le_bytes()))
        .boxed()
}

/// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
/// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) + q(.)`.
pub fn padd<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
where
    Field: FiniteField,
{
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p
        .iter()
        .cloned()
        .chain(std::iter::repeat(Field::ZERO).take(r_len - p.len()))
        .collect();
    let q0: Array1<_> = q
        .iter()
        .cloned()
        .chain(std::iter::repeat(Field::ZERO).take(r_len - q.len()))
        .collect();

    p0 + q0
}

/// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
/// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) - q(.)`.
pub fn psub<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
where
    Field: FiniteField,
{
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p
        .iter()
        .cloned()
        .chain(std::iter::repeat(Field::ZERO).take(r_len - p.len()))
        .collect();
    let q0: Array1<_> = q
        .iter()
        .cloned()
        .chain(std::iter::repeat(Field::ZERO).take(r_len - q.len()))
        .collect();

    p0 - q0
}
