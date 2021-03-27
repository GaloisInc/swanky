// Copyright (c) 2016 rust-threshold-secret-sharing developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Various number theoretic utility functions used in the library.

type Field = crate::f2_19x3_26::F;

/// Euclidean GCD implementation (recursive). The first member of the returned
/// triplet is the GCD of `a` and `b`.
pub fn gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let n = a / b;
        let c = a % b;
        let r = gcd(b, c);
        (r.0, r.2, r.1 - r.2 * n)
    }
}

#[test]
fn test_gcd() {
    assert_eq!(gcd(12, 16), (4, -1, 1));
}


/// Inverse of `k` in the *Zp* field defined by `prime`.
pub fn mod_inverse(k: i128, prime: i128) -> i128 {
    let k2 = k % prime;
    let r = if k2 < 0 {
        -gcd(prime, -k2).2
    } else {
        gcd(prime, k2).2
    };
    (prime + r) % prime
}

#[test]
fn test_mod_inverse() {
    assert_eq!(mod_inverse(3, 7), 5);
}


/// `x` to the power of `e` in the *Zp* field defined by `prime`.
pub fn mod_pow(mut x: i128, mut e: u64, prime: i128) -> i128 {
    let mut acc = 1;
    while e > 0 {
        if e % 2 == 0 {
            // even
            // no-op
        } else {
            // odd
            acc = (acc * x) % prime;
        }
        x = (x * x) % prime; // waste one of these by having it here but code is simpler (tiny bit)
        e = e >> 1;
    }
    acc
}

#[test]
fn test_mod_pow() {
    assert_eq!(mod_pow(2, 0, 17), 1);
    assert_eq!(mod_pow(2, 3, 17), 8);
    assert_eq!(mod_pow(2, 6, 17), 13);

    assert_eq!(mod_pow(-3, 0, 17), 1);
    assert_eq!(mod_pow(-3, 1, 17), -3);
    assert_eq!(mod_pow(-3, 15, 17), -6);
}


/// Compute the 2-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the lenght of `a_coef` as well as a power of 2.
/// The result will contains the same number of elements.
#[allow(dead_code)]
pub fn fft2(a_coef: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    crate::fft::fft2(&mut data, omega);
    data
}

/// Inverse FFT for `fft2`.
pub fn fft2_inverse(a_point: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_point.iter().cloned().collect();
    crate::fft::fft2_inverse(&mut data, omega);
    data
}

#[test]
fn test_fft2() {
    let omega = Field::ROOTS_BASE_2[8] as i128;
    let prime = Field::MOD as i128;

    let a_coef: Vec<_> = (1i128..=8).collect();
    assert_eq!(
        fft2(&a_coef.iter().cloned().map(Field::from).collect::<Vec<_>>(), Field::from(omega)),
        threshold_secret_sharing::numtheory::fft2(&a_coef, omega, prime)
            .iter().cloned().map(Field::from).collect::<Vec<_>>(),
    );
}

#[test]
fn test_fft2_inverse() {
    let omega = Field::ROOTS_BASE_2[8] as i128;
    let prime = Field::MOD as i128;

    let a_point: Vec<_> = (1i128..=8).collect();
    assert_eq!(
        fft2_inverse(&a_point.iter().cloned().map(Field::from).collect::<Vec<_>>(), Field::from(omega)),
        threshold_secret_sharing::numtheory::fft2_inverse(&a_point, omega, prime)
            .iter().cloned().map(Field::from).collect::<Vec<_>>(),
    );
}

/// Compute the 3-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the lenght of `a_coef` as well as a power of 3.
/// The result will contains the same number of elements.
pub fn fft3(a_coef: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    crate::fft::fft3(&mut data, omega);
    data
}

/// Inverse FFT for `fft3`.
#[allow(dead_code)]
pub fn fft3_inverse(a_point: &[Field], omega: Field) -> Vec<Field> {
    let mut data = a_point.iter().cloned().collect::<Vec<_>>();
    crate::fft::fft3_inverse(&mut data, omega);
    data
}

#[test]
fn test_fft3() {
    let omega = Field::ROOTS_BASE_3[9] as i128;
    let prime = Field::MOD as i128;

    let a_coef: Vec<_> = (1i128..=9).collect();
    assert_eq!(
        fft3(&a_coef.iter().cloned().map(Field::from).collect::<Vec<_>>(), Field::from(omega)),
        threshold_secret_sharing::numtheory::fft3(&a_coef, omega, prime)
            .iter().cloned().map(Field::from).collect::<Vec<_>>(),
    );
}

#[test]
fn test_fft3_inverse() {
    let omega = Field::ROOTS_BASE_3[9] as i128;
    let prime = Field::MOD as i128;

    let a_point: Vec<_> = (1i128..=9).collect();
    assert_eq!(
        fft3_inverse(&a_point.iter().cloned().map(Field::from).collect::<Vec<_>>(), Field::from(omega)),
        threshold_secret_sharing::numtheory::fft3_inverse(&a_point, omega, prime)
            .iter().cloned().map(Field::from).collect::<Vec<_>>(),
    );
}

/// Performs a Lagrange interpolation in field Zp at the origin
/// for a polynomial defined by `points` and `values`.
///
/// `points` and `values` are expected to be two arrays of the same size, containing
/// respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
///
/// The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.
///
/// This is obviously less general than `newton_interpolation_general` as we
/// only get a single value, but it is much faster.
pub fn lagrange_interpolation_at_zero(points: &[Field], values: &[Field]) -> Field {
    assert_eq!(points.len(), values.len());
    // Lagrange interpolation for point 0
    let mut acc = Field::ZERO;
    for i in 0..values.len() {
        let xi = points[i];
        let yi = values[i];
        let mut num = Field::ONE;
        let mut denum = Field::ONE;
        for j in 0..values.len() {
            if j != i {
                let xj = points[j];
                num = num * xj;
                denum = denum * (xj - xi);
            }
        }
        acc = acc + yi * num * denum.recip();
    }
    acc
}

/// Holds together points and Newton-interpolated coefficients for fast evaluation.
pub struct NewtonPolynomial<'a> {
    points: &'a [Field],
    coefficients: Vec<Field>,
}


/// General case for Newton interpolation in field Zp.
///
/// Given enough `points` (x) and `values` (p(x)), find the coefficients for `p`.
pub fn newton_interpolation_general<'a>(points: &'a [Field],
                                        values: &[Field])
                                        -> NewtonPolynomial<'a> {
    let coefficients = compute_newton_coefficients(points, values);
    NewtonPolynomial {
        points: points,
        coefficients: coefficients,
    }
}

#[test]
fn test_newton_interpolation_general() {
    let poly: Vec<_> = (1u64..=4).map(Field::from).collect();
    let points: Vec<_> = (5u64..=9).map(Field::from).collect();
    let values: Vec<Field> =
        points.iter().map(|&point| mod_evaluate_polynomial(&poly, point)).collect();

    let recovered_poly = newton_interpolation_general(&points, &values);
    let recovered_values: Vec<Field> =
        points.iter().map(|&point| newton_evaluate(&recovered_poly, point)).collect();
    assert_eq!(recovered_values, values);
}

pub fn newton_evaluate(poly: &NewtonPolynomial, point: Field) -> Field {
    // compute Newton points
    let mut newton_points = vec![Field::ONE];
    for i in 0..poly.points.len() - 1 {
        let diff = point - poly.points[i];
        let product = newton_points[i] * diff;
        newton_points.push(product);
    }
    let ref newton_coefs = poly.coefficients;
    // sum up
    newton_coefs.iter()
        .zip(newton_points)
        .map(|(&coef, point)| coef * point)
        .fold(Field::ZERO, |a, b| a + b)
}

fn compute_newton_coefficients(points: &[Field], values: &[Field]) -> Vec<Field> {
    assert_eq!(points.len(), values.len());

    let mut store: Vec<(usize, usize, Field)> =
        values.iter().enumerate().map(|(index, &value)| (index, index, value)).collect();

    for j in 1..store.len() {
        for i in (j..store.len()).rev() {
            let index_lower = store[i - 1].0;
            let index_upper = store[i].1;

            let point_lower = points[index_lower];
            let point_upper = points[index_upper];
            let point_diff = point_upper - point_lower;
            let point_diff_inverse = point_diff.recip();

            let coef_lower = store[i - 1].2;
            let coef_upper = store[i].2;
            let coef_diff = coef_upper - coef_lower;

            let fraction = coef_diff * point_diff_inverse;

            store[i] = (index_lower, index_upper, fraction);
        }
    }

    store.iter().map(|&(_, _, v)| v).collect()
}

/// Evaluate polynomial given by `coefficients` at `point` in Zp using Horner's method.
pub fn mod_evaluate_polynomial(coefficients: &[Field], point: Field) -> Field {
    // evaluate using Horner's rule
    //  - to combine with fold we consider the coefficients in reverse order
    let mut reversed_coefficients = coefficients.iter().rev();
    // manually split due to fold insisting on an initial value
    let head = *reversed_coefficients.next().unwrap();
    let tail = reversed_coefficients;
    tail.fold(head, |partial, &coef| partial * point + coef)
}
