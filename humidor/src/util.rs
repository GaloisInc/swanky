// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! Utility functions for Ligero

use ndarray::{Array1, ArrayView1};
use num_traits::identities::Zero;
use std::cmp::Eq;
use std::fmt::Debug;

use scuttlebutt::field::FiniteField;

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
pub type TestField = scuttlebutt::field::F2_19x3_26;
#[cfg(test)]
pub type TestHash = crate::merkle::Blake256;

#[cfg(test)]
pub fn arb_test_field() -> BoxedStrategy<TestField> {
    any::<u64>()
        .prop_map(|f| TestField::from(f as u128))
        .boxed()
}

/// Trait for collections that allow taking `n` initial elements while ensuring
/// that only zero-elements are dropped from the end.
pub trait TakeNZ
where
    Self: Sized,
{
    fn take_nz(self, n: usize) -> std::iter::Take<Self>;
}

impl<I: Zero + Eq + Debug, L> TakeNZ for L
where
    L: Iterator<Item = I> + Clone,
{
    #[inline]
    /// Take initial `n` elements, while ensuring (in debug builds) that the
    /// remaining elements are zeros.
    fn take_nz(self, n: usize) -> std::iter::Take<Self> {
        debug_assert!(self.clone().skip(n).all(|x| x.is_zero()));

        self.take(n)
    }
}

/// Given polynomials `p` and `q`, with `deg(p) < n` and `deg(q) < m`, return
/// the `n+m`-degree polynomial `r` with `r(x) = p(x)*q(x)`.
///
/// N.b.: This is the naive `O(n^2) algorithm. For `O(n log n)` performance on
/// polynomials of degree less than `k+1`, use `Params::pmul2`.
#[allow(dead_code)]
pub fn pmul<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
where
    Field: FiniteField + num_traits::Zero,
{
    let mut r = Array1::zeros(p.len() + q.len());

    for i in 0..p.len() {
        for j in 0..q.len() {
            r[i + j] += p[i] * q[j];
        }
    }

    r
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
