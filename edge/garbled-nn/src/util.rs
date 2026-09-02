//! Utility functions for working with [`NeuralNet`](crate::NeuralNet)s.

use fancy_circuits::util::{modulus_with_width, u128_from_bits};

/// Convert a list of bitwidths to their associated moduli.
pub fn bitwidths_to_moduli(bitwidths: &[usize]) -> Vec<u128> {
    bitwidths.iter().map(|&b| modulus_with_width(b)).collect()
}

/// The index of the max value in `xs`.
pub fn index_of_max(xs: &[i64]) -> usize {
    let mut max_val = i64::MIN;
    let mut max_ix = 0;
    for (i, &x) in xs.iter().enumerate() {
        if x > max_val {
            max_ix = i;
            max_val = x;
        }
    }
    max_ix
}

/// Negate `x` using two's complement.
pub fn twos_complement_negate(x: u128, nbits: usize) -> u128 {
    let mask = (1 << nbits) - 1;
    ((!x) & mask) + 1
}

/// Convert an `i64` to a `u128`, where negative values are converted using
/// two's complement.
pub fn i64_to_twos_complement(x: i64, nbits: usize) -> u128 {
    if x >= 0 {
        x as u128
    } else {
        twos_complement_negate((-x) as u128, nbits)
    }
}

/// Covert a `u128` to a `i64`, where negative values are converted using two's
/// complement.
pub fn i64_from_twos_complement(x: u128, nbits: usize) -> i64 {
    if x >= 1 << (nbits - 1) {
        -(twos_complement_negate(x, nbits) as i64)
    } else {
        x as i64
    }
}

/// Convert a sequence of bits into its `i64` representation.
pub fn i64_from_bits(bits: &[u16]) -> i64 {
    let x = u128_from_bits(bits);
    i64_from_twos_complement(x, bits.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn convert_binary() {
        let mut rng = rng();
        let nbits = 2 + rng.random_range(..120usize);
        for _ in 0..128 {
            let x = rng.random::<i64>() % nbits as i64;
            assert_eq!(
                x,
                i64_from_twos_complement(i64_to_twos_complement(x, nbits), nbits)
            );
        }
    }
}
