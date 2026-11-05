//! Utility functions.
//!
//! Note: all number representations are little-endian.

use swanky_field_binary::F2;

/// Convert a `u128` into a vector of `N` bits.
///
/// # Panics
/// Panics if `N > 128`.
pub(crate) fn u128_to_bits<const N: usize>(x: u128) -> [F2; N] {
    assert!(N <= 128);
    core::array::from_fn(|i| F2::from(((x >> i) & 1) != 0))
}

/// Convert a slice of bits into a `u128`.
///
/// # Panics
/// Panics if the slice length is greater than 128.
pub fn u128_from_bits(bits: &[F2]) -> u128 {
    assert!(bits.len() <= 128);
    let mut x = 0;
    for (i, bit) in bits.iter().enumerate() {
        x += (u16::from(*bit) as u128) << i;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn bits() {
        let mut rng = rng();
        for _ in 0..128 {
            let x = rng.random::<u128>();
            assert_eq!(u128_from_bits(&u128_to_bits::<128>(x)), x);
        }
    }
}
