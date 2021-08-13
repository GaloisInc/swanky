// Copyright (c) 2016 rust-threshold-secret-sharing developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Various number theoretic utility functions used in the library.
//!
//! Note: This library was adapted from
//! https://github.com/snipsco/rust-threshold-secret-sharing

use crate::field::FiniteField;

/// This trait indicates that a finite field is suitable for use in radix-2 FFT.
/// This means that it must have a power-of-two root of unity for any desired
/// FFT size, i.e., a field element `r_p`, such that `r_p^(2^p) = 1`, for a
/// size-`3^p` FFT. The `PHI_2_EXP` constant is the exponent of the largest FFT
/// size supported, and `roots_base_2` should return the `2^p`th root of unity.
pub trait FieldForFFT2: FiniteField + From<u128> {
    /// Largest integer `p` such that `phi(MODULUS) = 2^p * k` for integer `k`.
    const PHI_2_EXP: usize;

    /// For each `p` such that `2^p | phi(MODULUS)`, there is a `(2^p)`th root
    /// of unity, namely `r_p = GENERATOR^(phi(MODULUS) / 2^p)`, since then
    /// `r_p^(2^p) = GENERATOR^phi(MODULUS) = 1`. This function should return
    /// this `r_p`, on input `p`, for `p in [0 .. PHI_2_EXP]`.
    // [ GENERATOR^(phi(MODULUS) / (2^p)) % MODULUS | p <- [0 .. PHI_2_EXP] ]
    fn roots_base_2(p: usize) -> u128;
}

/// This trait indicates that a finite field is suitable for use in radix-3 FFT.
/// This means that it must have a power-of-three root of unity for any desired
/// FFT size, i.e., a field element `r_p`, such that `r_p^(3^p) = 1`, for a
/// size-`3^p` FFT. The `PHI_3_EXP` constant is the exponent of the largest FFT
/// size supported, and `roots_base_3` should return the `3^p`th root of unity.
pub trait FieldForFFT3: FiniteField + From<u128> {
    /// Largest integer `p` such that `phi(MODULUS) = 3^p * k` for integer `k`.
    const PHI_3_EXP: usize;

    /// For each `p` such that `3^p | phi(MODULUS)`, there is a `(3^p)`th root
    /// of unity, namely `r_p = GENERATOR^(phi(MODULUS) / 3^p)`, since then
    /// `r_p^(3^p) = GENERATOR^phi(MODULUS) = 1`. This function should return
    /// this `r_p`, on input `p`, for `p in [0 .. PHI_3_EXP]`.
    // [ GENERATOR^(phi(MODULUS) / (3^p)) % MODULUS | p <- [0 .. PHI_3_EXP] ]
    fn roots_base_3(p: usize) -> u128;
}

pub mod cooley_tukey {
    //! FFT by in-place Cooley-Tukey algorithms.

    use super::*;

    /// 2-radix FFT.
    ///
    /// * data is the data to transform
    ///
    /// `data.len()` must be a power of 2. omega must be a root of unity of order
    /// `data.len()`
    pub fn fft2<Field: FieldForFFT2>(data: &mut [Field], omega: Field) {
        fft2_in_place_rearrange(&mut *data);
        fft2_in_place_compute(&mut *data, omega);
    }

    /// 2-radix inverse FFT.
    ///
    /// * zp is the modular field
    /// * data is the data to transform
    /// * omega is the root-of-unity to use
    ///
    /// `data.len()` must be a power of 2. omega must be a root of unity of order
    /// `data.len()`
    pub fn fft2_inverse<Field: FieldForFFT2>(data: &mut [Field], omega: Field) {
        let omega_inv = omega.inverse();
        let len = data.len();
        let len_inv = Field::from(len as u128).inverse();
        fft2(data, omega_inv);
        for x in data {
            *x = *x * len_inv;
        }
    }

    fn fft2_in_place_rearrange<Field: FieldForFFT2>(data: &mut [Field]) {
        let mut target = 0;
        for pos in 0..data.len() {
            if target > pos {
                data.swap(target, pos)
            }
            let mut mask = data.len() >> 1;
            while target & mask != 0 {
                target &= !mask;
                mask >>= 1;
            }
            target |= mask;
        }
    }

    fn fft2_in_place_compute<Field: FieldForFFT2>(data: &mut [Field], omega: Field) {
        let mut depth = 0usize;
        while 1usize << depth < data.len() {
            let step = 1usize << depth;
            let jump = 2 * step;
            let factor_stride = omega.pow((data.len() / step / 2) as u128);
            let mut factor = Field::ONE;
            for group in 0usize..step {
                let mut pair = group;
                while pair < data.len() {
                    let (x, y) = (data[pair], data[pair + step] * factor);

                    data[pair] = x + y;
                    data[pair + step] = x - y;

                    pair += jump;
                }
                factor = factor * factor_stride;
            }
            depth += 1;
        }
    }

    /// 3-radix FFT.
    ///
    /// * zp is the modular field
    /// * data is the data to transform
    /// * omega is the root-of-unity to use
    ///
    /// `data.len()` must be a power of 2. omega must be a root of unity of order
    /// `data.len()`
    pub fn fft3<Field: FieldForFFT3>(data: &mut [Field], omega: Field)
    {
        fft3_in_place_rearrange(&mut *data);
        fft3_in_place_compute(&mut *data, omega);
    }

    /// 3-radix inverse FFT.
    ///
    /// * zp is the modular field
    /// * data is the data to transform
    /// * omega is the root-of-unity to use
    ///
    /// `data.len()` must be a power of 2. omega must be a root of unity of order
    /// `data.len()`
    pub fn fft3_inverse<Field>(data: &mut [Field], omega: Field)
        where Field: FieldForFFT3
    {
        let omega_inv = omega.inverse();
        let len_inv = Field::from(data.len() as u128).inverse();
        fft3(data, omega_inv);
        for x in data {
            *x = *x * len_inv;
        }
    }

    fn trigits_len(n: usize) -> usize {
        let mut result = 1;
        let mut value = 3;
        while value < n + 1 {
            result += 1;
            value *= 3;
        }
        result
    }

    fn fft3_in_place_rearrange<Field>(data: &mut [Field])
        where Field: FieldForFFT3
    {
        let mut target = 0isize;
        let trigits_len = trigits_len(data.len() - 1);
        let mut trigits: Vec<u8> = ::std::iter::repeat(0).take(trigits_len).collect();
        let powers: Vec<isize> = (0..trigits_len).map(|x| 3isize.pow(x as u32)).rev().collect();
        for pos in 0..data.len() {
            if target as usize > pos {
                data.swap(target as usize, pos)
            }
            for pow in 0..trigits_len {
                if trigits[pow] < 2 {
                    trigits[pow] += 1;
                    target += powers[pow];
                    break;
                } else {
                    trigits[pow] = 0;
                    target -= 2 * powers[pow];
                }
            }
        }
    }

    fn fft3_in_place_compute<Field>(data: &mut [Field], omega: Field)
        where Field: FieldForFFT3
    {
        let mut step = 1;
        let big_omega = omega.pow(data.len() as u128 / 3);
        let big_omega_sq = big_omega * big_omega;
        while step < data.len() {
            let jump = 3 * step;
            let factor_stride = omega.pow((data.len() / step / 3) as u128);
            let mut factor = Field::ONE;
            for group in 0usize..step {
                let factor_sq = factor * factor;
                let mut pair = group;
                while pair < data.len() {
                    let (x, y, z) = (data[pair],
                                     data[pair + step] * factor,
                                     data[pair + 2 * step] * factor_sq);

                    data[pair] = x + y + z;
                    data[pair + step] = x + big_omega*y + big_omega_sq*z;
                    data[pair + 2 * step] = x + big_omega_sq*y + big_omega*z;

                    pair += jump;
                }
                factor = factor * factor_stride;
            }
            step = jump;
        }
    }
}

/// Compute the 2-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the length of `a_coef` as well as a power of 2.
/// The result will contain the same number of elements.
#[allow(dead_code)]
pub fn fft2<Field>(a_coef: &[Field], omega: Field) -> Vec<Field>
    where Field: FieldForFFT2
{
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    cooley_tukey::fft2(&mut data, omega);
    data
}

/// Inverse FFT for `fft2`.
pub fn fft2_inverse<Field>(a_point: &[Field], omega: Field) -> Vec<Field>
    where Field: FieldForFFT2
{
    let mut data: Vec<_> = a_point.iter().cloned().collect();
    cooley_tukey::fft2_inverse(&mut data, omega);
    data
}

/// Tests for types implementing FieldForFFT2
#[macro_export]
macro_rules! fft2_tests {
    ($field: ty) => {
        #[test]
        fn test_fft2() {
            let omega = <$field>::roots_base_2(8) as u128;
            let prime = <$field>::MODULUS as u128;

            let a_coef: Vec<_> = (1u128..=8).collect();
            assert_eq!(
                fft2(&a_coef.iter().cloned().map(<$field>::from).collect::<Vec<_>>(), <$field>::from(omega)),
                threshold_secret_sharing::numtheory::fft2(&a_coef, omega, prime)
                    .iter().cloned().map(<$field>::from).collect::<Vec<_>>(),
            );
        }

        #[test]
        fn test_fft2_inverse() {
            let omega = <$field>::roots_base_2(8) as u128;
            let prime = <$field>::MODULUS as u128;

            let a_point: Vec<_> = (1u128..=8).collect();
            assert_eq!(
                fft2_inverse(&a_point.iter().cloned().map(<$field>::from).collect::<Vec<_>>(), <$field>::from(omega)),
                threshold_secret_sharing::numtheory::fft2_inverse(&a_point, omega, prime)
                    .iter().cloned().map(<$field>::from).collect::<Vec<_>>(),
            );
        }

        #[test]
        fn test_fft2_big() {
            let mut data: Vec<_> = (0u128..256).map(<$field>::from).collect();
            data = fft2(&data, <$field>::from(<$field>::roots_base_2(8)));
            data = fft2_inverse(&data, <$field>::from(<$field>::roots_base_2(8)));

            assert_eq!(
                data.iter().cloned().map(u128::from).collect::<Vec<_>>(),
                (0..256).collect::<Vec<_>>(),
            );
        }
    }
}

/// Compute the 3-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the length of `a_coef` as well as a power of 3.
/// The result will contain the same number of elements.
pub fn fft3<Field>(a_coef: &[Field], omega: Field) -> Vec<Field>
    where Field: FieldForFFT3
{
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    cooley_tukey::fft3(&mut data, omega);
    data
}

/// Inverse FFT for `fft3`.
#[allow(dead_code)]
pub fn fft3_inverse<Field>(a_point: &[Field], omega: Field) -> Vec<Field>
    where Field: FieldForFFT3
{
    let mut data = a_point.iter().cloned().collect::<Vec<_>>();
    cooley_tukey::fft3_inverse(&mut data, omega);
    data
}

/// Tests for types implementing FieldForFFT3
#[macro_export]
macro_rules! fft3_tests {
    ($field: ty) => {
        #[test]
        fn test_fft3() {
            let omega = <$field>::roots_base_3(9) as u128;
            let prime = <$field>::MODULUS as u128;

            let a_coef: Vec<_> = (1u128..=9).collect();
            assert_eq!(
                fft3(&a_coef.iter().cloned().map(<$field>::from).collect::<Vec<_>>(), <$field>::from(omega)),
                threshold_secret_sharing::numtheory::fft3(&a_coef, omega, prime)
                    .iter().cloned().map(<$field>::from).collect::<Vec<_>>(),
            );
        }

        #[test]
        fn test_fft3_inverse() {
            let omega = <$field>::roots_base_3(9) as u128;
            let prime = <$field>::MODULUS as u128;

            let a_point: Vec<_> = (1u128..=9).collect();
            assert_eq!(
                fft3_inverse(&a_point.iter().cloned().map(<$field>::from).collect::<Vec<_>>(), <$field>::from(omega)),
                threshold_secret_sharing::numtheory::fft3_inverse(&a_point, omega, prime)
                    .iter().cloned().map(<$field>::from).collect::<Vec<_>>(),
            );
        }

        #[test]
        fn test_fft3_big() {
            let mut data: Vec<_> = (0u128..19683).map(<$field>::from).collect();
            data = fft3(&data, <$field>::from(<$field>::roots_base_3(9)));
            data = fft3_inverse(&data, <$field>::from(<$field>::roots_base_3(9)));

            assert_eq!(
                data.iter().cloned().map(u128::from).collect::<Vec<_>>(),
                (0..19683).collect::<Vec<_>>(),
            );
        }
    }
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
pub fn lagrange_interpolation_at_zero<Field>(points: &[Field], values: &[Field]) -> Field
    where Field: FiniteField
{
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
        acc = acc + yi * num * denum.inverse();
    }
    acc
}

/// Holds together points and Newton-interpolated coefficients for fast evaluation.
pub struct NewtonPolynomial<'a, Field>
    where Field: FiniteField
{
    points: &'a [Field],
    coefficients: Vec<Field>,
}

/// General case for Newton interpolation in field Zp.
///
/// Given enough `points` (x) and `values` (p(x)), find the coefficients for `p`.
pub fn newton_interpolation_general<'a, Field>(
    points: &'a [Field],
    values: &[Field]
) -> NewtonPolynomial<'a, Field>
    where Field: FiniteField
{
    let coefficients = compute_newton_coefficients(points, values);
    NewtonPolynomial {
        points: points,
        coefficients: coefficients,
    }
}

/// Newton interpolation tests for types implementing FiniteField
#[macro_export]
macro_rules! interpolation_tests {
    ($field: ty) => {
        #[test]
        fn test_newton_interpolation_general() {
            let poly: Vec<_> = (1u64..=4).map(<$field>::from).collect();
            let points: Vec<_> = (5u64..=9).map(<$field>::from).collect();
            let values: Vec<$field> =
                points.iter().map(|&point| mod_evaluate_polynomial(&poly, point)).collect();

            let recovered_poly = newton_interpolation_general(&points, &values);
            let recovered_values: Vec<$field> =
                points.iter().map(|&point| newton_evaluate(&recovered_poly, point)).collect();
            assert_eq!(recovered_values, values);
        }
    }
}

/// Evaluate a Newton polynomial
pub fn newton_evaluate<Field>(poly: &NewtonPolynomial<Field>, point: Field) -> Field
    where Field: FiniteField
{
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

fn compute_newton_coefficients<Field>(points: &[Field], values: &[Field]) -> Vec<Field>
    where Field: FiniteField
{
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
            let point_diff_inverse = point_diff.inverse();

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
pub fn mod_evaluate_polynomial<Field>(coefficients: &[Field], point: Field) -> Field
    where Field: FiniteField
{
    // evaluate using Horner's rule
    //  - to combine with fold we consider the coefficients in reverse order
    let mut reversed_coefficients = coefficients.iter().rev();
    // manually split due to fold insisting on an initial value
    let head = *reversed_coefficients.next().unwrap();
    let tail = reversed_coefficients;
    tail.fold(head, |partial, &coef| partial * point + coef)
}
