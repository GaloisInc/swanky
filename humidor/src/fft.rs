// Copyright (c) 2016 rust-threshold-secret-sharing developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! FFT by in-place Cooley-Tukey algorithms.

type Field = crate::f2_19x3_26::F;

/// 2-radix FFT.
///
/// * data is the data to transform
///
/// `data.len()` must be a power of 2. omega must be a root of unity of order
/// `data.len()`
pub fn fft2(data: &mut [Field], omega: Field) {
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
pub fn fft2_inverse(data: &mut [Field], omega: Field) {
    let omega_inv = Field::from(omega).recip();
    let len = data.len();
    let len_inv = Field::from(len as i128).recip();
    fft2(data, omega_inv);
    for x in data {
        *x = *x * len_inv;
    }
}

fn fft2_in_place_rearrange(data: &mut [Field]) {
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

fn fft2_in_place_compute(data: &mut [Field], omega: Field) {
    let mut depth = 0usize;
    while 1usize << depth < data.len() {
        let step = 1usize << depth;
        let jump = 2 * step;
        let factor_stride = omega.pow((data.len() / step / 2) as u64);
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
pub fn fft3(data: &mut [Field], omega: Field) {
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
pub fn fft3_inverse(data: &mut [Field], omega: Field) {
    let omega_inv = omega.recip();
    let len_inv = Field::from(data.len() as u128).recip();
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

fn fft3_in_place_rearrange(data: &mut [Field]) {
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

fn fft3_in_place_compute(data: &mut [Field], omega: Field) {
    let mut step = 1;
    let big_omega = omega.pow(data.len() as u64 / 3);
    let big_omega_sq = big_omega * big_omega;
    while step < data.len() {
        let jump = 3 * step;
        let factor_stride = omega.pow((data.len() / step / 3) as u64);
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

#[cfg(test)]
mod test {
    use super::*;

    fn from(data: &[u128]) -> Vec<Field> {
        data.iter().cloned().map(Field::from).collect()
    }

    fn back(data: &[Field]) -> Vec<u128> {
        data.iter().cloned().map(u128::from).collect()
    }

    #[test]
    fn test_fft2_big() {
        let mut data: Vec<_> = (0u128..256).map(Field::from).collect();
        fft2(&mut *data, Field::from(Field::ROOTS_BASE_2[8]));
        fft2_inverse(&mut data, Field::from(Field::ROOTS_BASE_2[8]));

        assert_eq!(back(&data), (0..256).collect::<Vec<_>>());
    }

    #[test]
    fn test_fft3_big() {
        let mut data: Vec<_> = (0u128..19683).map(Field::from).collect();
        fft3(&mut data, Field::from(Field::ROOTS_BASE_3[9]));
        fft3_inverse(&mut data, Field::from(Field::ROOTS_BASE_3[9]));

        assert_eq!(back(&data), (0..19683).collect::<Vec<_>>());
    }
}
