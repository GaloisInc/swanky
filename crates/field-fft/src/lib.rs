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

use swanky_field::FiniteField;

/// This trait indicates that a finite field is suitable for use in radix-`N` FFT.
/// This means that it must have a power-of-`N` root of unity for any desired
/// FFT size, i.e., a field element `r_p`, such that `r_p^(N^p) = 1`, for a
/// size-`3^p` FFT. The `PHI_EXP` constant is the exponent of the largest FFT
/// size supported, and `root` should return the `N^p`th root of unity.
pub trait FieldForFFT<const N: usize>: FiniteField + TryFrom<u128> {
    /// Largest integer `p` such that `phi(MODULUS) = N^p * k` for integer `k`.
    const PHI_EXP: usize;

    /// For each `p` such that `N^p | phi(MODULUS)`, there is a `(N^p)`th root
    /// of unity, namely `r_p = GENERATOR^(phi(MODULUS) / N^p)`, since then
    /// `r_p^(N^p) = GENERATOR^phi(MODULUS) = 1`. This function should return
    /// this `r_p`, on input `p`, for `p in [0 .. PHI_EXP]`.
    // [ GENERATOR^(phi(MODULUS) / (N^p)) % MODULUS | p <- [0 .. PHI_EXP] ]
    fn roots(p: usize) -> Self;
}

mod cooley_tukey {
    //! FFT by in-place Cooley-Tukey algorithms.

    use super::*;

    /// 2-radix FFT.
    ///
    /// * data is the data to transform
    ///
    /// `data.len()` must be a power of 2. omega must be a root of unity of order
    /// `data.len()`
    pub(super) fn fft2<Field: FieldForFFT<2>>(data: &mut [Field], omega: Field) {
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
    pub(super) fn fft2_inverse<Field: FieldForFFT<2>>(data: &mut [Field], omega: Field) {
        let omega_inv = omega.inverse();
        let len = data.len();
        let len_inv = Field::try_from(len as u128)
            .unwrap_or_else(|_| unreachable!()) // data length should always be small enough
            .inverse();
        fft2(data, omega_inv);
        for x in data {
            *x *= len_inv;
        }
    }

    fn fft2_in_place_rearrange<Field: FieldForFFT<2>>(data: &mut [Field]) {
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

    fn fft2_in_place_compute<Field: FieldForFFT<2>>(data: &mut [Field], omega: Field) {
        let mut depth = 0usize;
        while 1usize << depth < data.len() {
            let step = 1usize << depth;
            let jump = 2 * step;
            let factor_stride = omega.pow_var_time((data.len() / step / 2) as u128);
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
    pub(super) fn fft3<Field: FieldForFFT<3>>(data: &mut [Field], omega: Field) {
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
    pub(super) fn fft3_inverse<Field: FieldForFFT<3>>(data: &mut [Field], omega: Field) {
        let omega_inv = omega.inverse();
        let len_inv = Field::try_from(data.len() as u128)
            .unwrap_or_else(|_| unreachable!()) // data length should always be small enough
            .inverse();
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

    fn fft3_in_place_rearrange<Field: FieldForFFT<3>>(data: &mut [Field]) {
        let mut target = 0isize;
        let trigits_len = trigits_len(data.len() - 1);
        let mut trigits: Vec<u8> = ::std::iter::repeat(0).take(trigits_len).collect();
        let powers: Vec<isize> = (0..trigits_len)
            .map(|x| 3isize.pow(x as u32))
            .rev()
            .collect();
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

    fn fft3_in_place_compute<Field: FieldForFFT<3>>(data: &mut [Field], omega: Field) {
        let mut step = 1;
        let big_omega = omega.pow_var_time(data.len() as u128 / 3);
        let big_omega_sq = big_omega * big_omega;
        while step < data.len() {
            let jump = 3 * step;
            let factor_stride = omega.pow_var_time((data.len() / step / 3) as u128);
            let mut factor = Field::ONE;
            for group in 0usize..step {
                let factor_sq = factor * factor;
                let mut pair = group;
                while pair < data.len() {
                    let (x, y, z) = (
                        data[pair],
                        data[pair + step] * factor,
                        data[pair + 2 * step] * factor_sq,
                    );

                    data[pair] = x + y + z;
                    data[pair + step] = x + big_omega * y + big_omega_sq * z;
                    data[pair + 2 * step] = x + big_omega_sq * y + big_omega * z;

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
pub fn fft2<Field: FieldForFFT<2>>(a_coef: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    cooley_tukey::fft2(&mut data, omega);
    data
}

/// Compute the in-place 2-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the length of `a_coef` as well as a power of 2.
/// The result will contain the same number of elements.
pub fn fft2_in_place<Field: FieldForFFT<2>>(a_coef: &mut [Field], omega: Field) {
    cooley_tukey::fft2(a_coef, omega);
}

/// Inverse FFT for `fft2`.
pub fn fft2_inverse<Field: FieldForFFT<2>>(a_point: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_point.iter().cloned().collect();
    cooley_tukey::fft2_inverse(&mut data, omega);
    data
}

/// Inverse FFT for `fft2_in_place`.
pub fn fft2_inverse_in_place<Field: FieldForFFT<2>>(a_point: &mut [Field], omega: Field) {
    cooley_tukey::fft2_inverse(a_point, omega);
}

/// Compute the 3-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the length of `a_coef` as well as a power of 3.
/// The result will contain the same number of elements.
pub fn fft3<Field: FieldForFFT<3>>(a_coef: &[Field], omega: Field) -> Vec<Field> {
    let mut data: Vec<_> = a_coef.iter().cloned().collect();
    cooley_tukey::fft3(&mut data, omega);
    data
}

/// Compute the 3-radix FFT of `a_coef` in the *Zp* field defined by `prime`.
///
/// `omega` must be a `n`-th principal root of unity,
/// where `n` is the length of `a_coef` as well as a power of 3.
/// The result will contain the same number of elements.
pub fn fft3_in_place<Field: FieldForFFT<3>>(a_coef: &mut [Field], omega: Field) {
    cooley_tukey::fft3(a_coef, omega);
}

/// Inverse FFT for `fft3`.
pub fn fft3_inverse<Field: FieldForFFT<3>>(a_point: &[Field], omega: Field) -> Vec<Field> {
    let mut data = a_point.iter().cloned().collect::<Vec<_>>();
    cooley_tukey::fft3_inverse(&mut data, omega);
    data
}

/// Inverse FFT for `fft3`.
pub fn fft3_inverse_in_place<Field: FieldForFFT<3>>(a_point: &mut [Field], omega: Field) {
    cooley_tukey::fft3_inverse(a_point, omega);
}

/// Performs a Lagrange interpolation at the origin for a polynomial defined by
/// `points` and `values`.
///
/// `points` and `values` are expected to be two arrays of the same size, containing
/// respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
///
/// The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.
///
/// This is obviously less general than `newton_interpolation_general` as we
/// only get a single value, but it is much faster.
pub fn lagrange_interpolation_at_zero<Field>(points: &[Field], values: &[Field]) -> Field
where
    Field: FiniteField,
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

#[cfg(test)]
mod tests {
    // use super::*;

    // /// Tests for types implementing FieldForFFT2
    // macro_rules! fft2_tests {
    //     ($field: ty) => {
    //         #[test]
    //         fn test_fft2() {
    //             let omega = <$field>::roots_base_2(8) as u128;
    //             let prime = <$field>::MODULUS as u128;

    //             let a_coef: Vec<_> = (1u128..=8).collect();
    //             assert_eq!(
    //                 fft2(
    //                     &a_coef
    //                         .iter()
    //                         .cloned()
    //                         .map(<$field>::from)
    //                         .collect::<Vec<_>>(),
    //                     <$field>::from(omega)
    //                 ),
    //                 threshold_secret_sharing::numtheory::fft2(&a_coef, omega, prime)
    //                     .iter()
    //                     .cloned()
    //                     .map(<$field>::from)
    //                     .collect::<Vec<_>>(),
    //             );
    //         }

    //         #[test]
    //         fn test_fft2_inverse() {
    //             let omega = <$field>::roots_base_2(8) as u128;
    //             let prime = <$field>::MODULUS as u128;

    //             let a_point: Vec<_> = (1u128..=8).collect();
    //             assert_eq!(
    //                 fft2_inverse(
    //                     &a_point
    //                         .iter()
    //                         .cloned()
    //                         .map(<$field>::from)
    //                         .collect::<Vec<_>>(),
    //                     <$field>::from(omega)
    //                 ),
    //                 threshold_secret_sharing::numtheory::fft2_inverse(&a_point, omega, prime)
    //                     .iter()
    //                     .cloned()
    //                     .map(<$field>::from)
    //                     .collect::<Vec<_>>(),
    //             );
    //         }

    //         #[test]
    //         fn test_fft2_big() {
    //             let mut data: Vec<_> = (0u128..256).map(<$field>::from).collect();
    //             data = fft2(&data, <$field>::from(<$field>::roots_base_2(8)));
    //             data = fft2_inverse(&data, <$field>::from(<$field>::roots_base_2(8)));

    //             assert_eq!(
    //                 data.iter().cloned().map(u128::from).collect::<Vec<_>>(),
    //                 (0..256).collect::<Vec<_>>(),
    //             );
    //         }
    //     };
    // }

    // fft2_tests!(F2_19x3_26);

    // /// Tests for types implementing FieldForFFT3
    // macro_rules! fft3_tests {
    //     ($field: ty) => {
    //         #[test]
    //         fn test_fft3() {
    //             let omega = <$field>::roots_base_3(9) as u128;
    //             let prime = <$field>::MODULUS as u128;

    //             let a_coef: Vec<_> = (1u128..=9).collect();
    //             assert_eq!(
    //                 fft3(
    //                     &a_coef
    //                         .iter()
    //                         .cloned()
    //                         .map(<$field>::from)
    //                         .collect::<Vec<_>>(),
    //                     <$field>::from(omega)
    //                 ),
    //                 fft3(&a_coef, omega, prime)
    //                     .iter()
    //                     .cloned()
    //                     .map(<$field>::from)
    //                     .collect::<Vec<_>>(),
    //             );
    //         }

    //         #[test]
    //         fn test_fft3_inverse() {
    //             let omega = <$field>::roots_base_3(9) as u128;
    //             let prime = <$field>::MODULUS as u128;

    //             let a_point: Vec<_> = (1u128..=9).collect();
    //             assert_eq!(
    //                 fft3_inverse(
    //                     &a_point
    //                         .iter()
    //                         .cloned()
    //                         .map(<$field>::from)
    //                         .collect::<Vec<_>>(),
    //                     <$field>::from(omega)
    //                 ),
    //                 threshold_secret_sharing::numtheory::fft3_inverse(&a_point, omega, prime)
    //                     .iter()
    //                     .cloned()
    //                     .map(<$field>::from)
    //                     .collect::<Vec<_>>(),
    //             );
    //         }

    //         #[test]
    //         fn test_fft3_big() {
    //             let mut data: Vec<_> = (0u128..19683).map(<$field>::from).collect();
    //             data = fft3(&data, <$field>::from(<$field>::roots_base_3(9)));
    //             data = fft3_inverse(&data, <$field>::from(<$field>::roots_base_3(9)));

    //             assert_eq!(
    //                 data.iter().cloned().map(u128::from).collect::<Vec<_>>(),
    //                 (0..19683).collect::<Vec<_>>(),
    //             );
    //         }
    //     };
    // }

    // fft3_tests!(F2_19x3_26);
}
