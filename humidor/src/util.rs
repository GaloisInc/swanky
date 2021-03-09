use ndarray::{Array1, ArrayView1};

type Field = crate::f5038849::F;

// Return the least `p` s.t. `3^p >= n`.
#[inline]
pub fn next_three_power(n: usize) -> u32 {
    next_power_of_b(n, 2)
}

// Return the least `m = 3^p` s.t. `m >= n`.
#[inline]
pub fn next_power_of_three(n: usize) -> usize {
    3usize.pow(next_three_power(n))
}

// Return the least `p` s.t. `2^p >= n`.
#[inline]
pub fn next_two_power(n: usize) -> u32 {
    next_power_of_b(n, 2)
}

// Return the least `p` s.t. `b^p >= n`.
fn next_power_of_b(n: usize, b: usize) -> u32 {
    let mut m = 1;
    let mut p = 0;

    while m < n {
        m *= b;
        p += 1;
    }

    p
}

// Given polynomials `p` and `q`, with `deg(p) < n` and `deg(q) < m`, return
// the `n`-degree polynomial `r` with `r(x) = p(x)*q(x)`.
pub fn pmul(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field> {
    let mut r = Array1::zeros(p.len() + q.len());

    for i in 0 .. p.len() {
        for j in 0 .. q.len() {
            r[i + j] += p[i] * q[j];
        }
    }

    r
}

// Evaluate a polynomial, represented by its coefficients, at a point `x`.
pub fn peval(p: ArrayView1<Field>, x: Field) -> Field {
    let mut res = Field::ZERO;

    for &pi in p.to_vec()[1..].iter().rev() {
        res = res + pi;
        res = res * x;
    }

    res + p[0]
}

pub fn point_product(u: ArrayView1<Field>, v: ArrayView1<Field>) -> Array1<Field> {
    debug_assert_eq!(u.len(), v.len());

    Array1::from_shape_fn(u.len(), |i| u[i] * v[i])
}

pub fn pad_or_unpad(a: ArrayView1<Field>, size: usize) -> Array1<Field> {
    let dim = a.len();

    if dim == size {
        a.to_owned()
    } else if dim > size {
        unpad_array(a, size)
    } else {
        pad_array(a, size)
    }
}

#[inline]
pub fn pad_array(a: ArrayView1<Field>, size: usize) -> Array1<Field> {
    debug_assert!(a.len() <= size);

    let mut res = Array1::zeros(size);
    res.slice_mut(ndarray::s!(0 .. a.len())).assign(&a);

    res
}

#[inline]
pub fn unpad_array(a: ArrayView1<Field>, size: usize) -> Array1<Field> {
    debug_assert!(a.len() >= size);

    let (a1, a2) = a.split_at(ndarray::Axis(0), size);

    debug_assert_eq!(a2, Array1::zeros(a2.len()).view());
    a1.to_owned()
}

pub fn trim_zeros<T>(mut v: Vec<T>) -> Vec<T> 
    where T: num_traits::identities::Zero + Eq
{
    while v.last() == Some(&T::zero()) {
        v.pop();
    }

    v
}
