use ndarray::{Array1, ArrayView1, Array2};
use num_traits::identities::Zero;
use std::cmp::Eq;
use std::fmt::Debug;

use scuttlebutt::field::FiniteField;
use scuttlebutt::numtheory;

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
pub type TestField = scuttlebutt::field::F2_19x3_26;

#[cfg(test)]
pub fn arb_test_field() -> BoxedStrategy<TestField> {
    (0..TestField::MODULUS as u128).prop_map(|n| n.into()).boxed()
}

// Trait for collections that allow taking `n` initial elements while ensuring
// that only zero-elements are dropped from the end.
pub trait TakeNZ where Self: Sized {
    fn take_nz(self, n: usize) -> std::iter::Take<Self>;
}

impl<I: Zero + Eq + Debug, L> TakeNZ for L where L: Iterator<Item = I> + Clone {
    #[inline]
    fn take_nz(self, n: usize) -> std::iter::Take<Self> {
        debug_assert_eq!(
            self.clone().skip(n).collect::<Vec<_>>(),
            self.clone().skip(n).map(|_| I::zero()).collect::<Vec<_>>(),
        );

        self.take(n)
    }
}

pub fn rows_to_mat<S: Clone>(rows: Vec<Array1<S>>) -> Array2<S> {
    let nrows = rows.len();
    let ncols = rows[0].len();

    Array2::from_shape_vec((nrows, ncols),
        rows.iter()
            .map(|r| r.into_iter().cloned())
            .flatten()
            .collect::<Vec<S>>()
    ).expect("Unequal matrix rows")
}

/// Given polynomials `p` and `q`, with `deg(p) < n` and `deg(q) < m`, return
/// the `n+m`-degree polynomial `r` with `r(x) = p(x)*q(x)`.
///
/// N.b.: This is the naive `O(n^2) algorithm. For `O(n log n)` performance on
/// polynomials of degree less than `k+1`, use `Params::pmul2`.
#[allow(dead_code)]
pub fn pmul<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
    where Field: FiniteField + num_traits::Zero
{
    let mut r = Array1::zeros(p.len() + q.len());

    for i in 0 .. p.len() {
        for j in 0 .. q.len() {
            r[i + j] += p[i] * q[j];
        }
    }

    r
}

// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) + q(.)`.
pub fn padd<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
    where Field: FiniteField
{
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - p.len()])
        .collect();
    let q0: Array1<_> = q.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - q.len()])
        .collect();

    p0 + q0
}

// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) - q(.)`.
pub fn psub<Field>(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field>
    where Field: FiniteField
{
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - p.len()])
        .collect();
    let q0: Array1<_> = q.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - q.len()])
        .collect();

    p0 - q0
}

// Evaluate a polynomial, represented by its coefficients, at a point `x`.
pub fn peval<Field: FiniteField>(p: ArrayView1<Field>, x: Field) -> Field {
    //let mut res = Field::ZERO;

    //for &pi in p.to_vec()[1..].iter().rev() {
    //    res = res + pi;
    //    res = res * x;
    //}

    //res + p[0]
    numtheory::mod_evaluate_polynomial(&p.to_vec(), x)
}

pub fn random_field_array<R: rand::Rng, Field: FiniteField>(
    rng: &mut R, size: usize
) -> Array1<Field> {
    (0 .. size).map(|_| Field::random(rng)).collect()
}
