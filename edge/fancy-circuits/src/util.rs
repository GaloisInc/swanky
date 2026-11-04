//! Utility functions.
//!
//! Note: all number representations are little-endian.

use swanky_field_binary::F2;

/// Convert a `u128` into a vector of bits.
pub(crate) fn u128_to_bits(x: u128, nbits: usize) -> Vec<F2> {
    let mut bits = Vec::with_capacity(nbits);
    let mut y = x;
    for _ in 0..nbits {
        let b = y & 1;
        bits.push((b != 0).into());
        y -= b;
        y /= 2;
    }
    bits
}

/// Convert a vector of bits into a `u128`.
pub fn u128_from_bits(bs: &[F2]) -> u128 {
    let mut x = 0;
    for &b in bs.iter().skip(1).rev() {
        x += (u16::from(b)) as u128;
        x *= 2;
    }
    x += u16::from(bs[0]) as u128;
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
            assert_eq!(u128_from_bits(&u128_to_bits(x, 128)), x);
        }
    }
}
