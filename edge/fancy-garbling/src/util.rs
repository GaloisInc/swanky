//! Tools useful for interacting with `fancy-garbling`.
//!
//! Note: all number representations in this library are little-endian.

use rand::RngExt as _;

use fancy_circuits::util::as_mixed_radix;
use vectoreyes::U8x16;

/// Tweak function for two items.
pub(crate) fn tweak2(i: u64, j: u64) -> u128 {
    (j as u128) << 64 | (i as u128)
}

/// Compute the output tweak for a garbled gate where `i`` is the gate ID and
/// `k` is the value.
pub fn output_tweak(i: usize, k: u16) -> u128 {
    let (left, _) = (i as u128).overflowing_shl(64);
    left + k as u128
}

/// Determine how many `mod q` digits fit into a `u128` (includes the color
/// digit).
pub(crate) fn digits_per_u128(modulus: u16) -> usize {
    debug_assert_ne!(modulus, 0);
    debug_assert_ne!(modulus, 1);
    if modulus == 2 {
        128
    } else if modulus <= 4 {
        64
    } else if modulus <= 8 {
        42
    } else if modulus <= 16 {
        32
    } else if modulus <= 32 {
        25
    } else if modulus <= 64 {
        21
    } else if modulus <= 128 {
        18
    } else if modulus <= 256 {
        16
    } else if modulus <= 512 {
        14
    } else {
        (128.0 / (modulus as f64).log2().ceil()).floor() as usize
    }
}

/// Convert little-endian base `q` digits into `u128`.
pub(crate) fn from_base_q(ds: &[u16], q: u16) -> u128 {
    let mut x = 0u128;
    for &d in ds.iter().rev() {
        let (xp, overflow) = x.overflowing_mul(q.into());
        debug_assert!(!overflow, "overflow!!!! x={}", x);
        x = xp + d as u128;
    }
    x
}

/// Convert `x` into base `q`, building a vector of length `n`.
fn as_base_q(x: u128, q: u16, n: usize) -> Vec<u16> {
    let ms = core::iter::repeat_n(q, n).collect::<Vec<_>>();
    as_mixed_radix(x, &ms)
}

/// Convert `x` into base `q`.
pub fn as_base_q_u128(x: u128, q: u16) -> Vec<u16> {
    as_base_q(x, q, digits_per_u128(q))
}

/// Extra [`rand::Rng`] functionality, useful for testing.
pub trait RngExt: rand::Rng + Sized {
    /// Randomly generate a valid `Block`.
    fn gen_usable_block(&mut self, modulus: u16) -> U8x16 {
        if modulus.is_power_of_two() {
            let nbits = (modulus - 1).count_ones();
            if 128 % nbits == 0 {
                return U8x16::from(self.random::<u128>());
            }
        }
        let n = digits_per_u128(modulus);
        let max = (modulus as u128).pow(n as u32);
        U8x16::from(self.random::<u128>() % max)
    }
}

impl<R: rand::Rng + Sized> RngExt for R {}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_circuits::util::RngExt as _;
    use rand::rng;

    #[test]
    fn base_q_conversion() {
        let mut rng = rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = u128::from(rng.gen_usable_block(q));
            let y = as_base_q(x, q, digits_per_u128(q));
            let z = from_base_q(&y, q);
            assert_eq!(x, z);
        }
    }
}
