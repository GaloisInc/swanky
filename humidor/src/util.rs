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

//#[test]
//fn test_pmul() {
//    let p = Public::test_value();
//    let dim = (p.k + 1) as i64;
//
//    let u = (0 .. dim).collect::<Vec<i64>>();
//    let u_coeffs = threshold_secret_sharing::numtheory::fft2_inverse(
//        &u,
//        p.pss.omega_secrets,
//        p.pss.prime,
//    ).iter().cloned().map(Field::from).collect::<Array1<Field>>();
//
//    let v = (dim .. 2*dim).collect::<Vec<i64>>();
//    let v_coeffs = threshold_secret_sharing::numtheory::fft2_inverse(
//        &v,
//        p.pss.omega_secrets,
//        p.pss.prime,
//    ).iter().cloned().map(Field::from).collect::<Array1<Field>>();
//
//    let uv_coeffs = pmul(u_coeffs.view(), v_coeffs.view());
//
//    for i in 0 .. u.len() {
//        debug_assert_eq!(
//            p.peval2(uv_coeffs.view(), i),
//            Field::from(u[i] * v[i]),
//        );
//    }
//}
