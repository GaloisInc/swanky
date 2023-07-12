//! Tools useful for interacting with `fancy-garbling`.
//!
//! Note: all number representations in this library are little-endian.

use itertools::Itertools;
use scuttlebutt::Block;
use std::collections::HashMap;
use vectoreyes::{SimdBase, U64x2, U8x16};

use crate::WireLabel;

////////////////////////////////////////////////////////////////////////////////
// tweak functions for garbling

/// Tweak function for a single item.
pub fn tweak(i: usize) -> Block {
    Block::from(U8x16::from(U64x2::set_lo(i as u64)))
}

/// Tweak function for two items.
pub fn tweak2(i: u64, j: u64) -> Block {
    Block::from(U8x16::from(U64x2::from([j, i])))
}

/// Compute the output tweak for a garbled gate where i is the gate id and k is the value.
pub fn output_tweak(i: usize, k: u16) -> Block {
    let (left, _) = (i as u128).overflowing_shl(64);
    Block::from(left + k as u128)
}

////////////////////////////////////////////////////////////////////////////////
// mixed radix stuff

/// Add a base `q` slice `ys` into `xs`.
pub fn base_q_add_eq(xs: &mut [u16], ys: &[u16], q: u16) {
    debug_assert!(
        xs.len() >= ys.len(),
        "q={} xs.len()={} ys.len()={} xs={:?} ys={:?}",
        q,
        xs.len(),
        ys.len(),
        xs,
        ys
    );

    let mut c = 0;
    let mut i = 0;

    while i < ys.len() {
        xs[i] += ys[i] + c;
        c = (xs[i] >= q) as u16;
        xs[i] -= c * q;
        i += 1;
    }

    // continue the carrying if possible
    while i < xs.len() {
        xs[i] += c;
        if xs[i] >= q {
            xs[i] -= q;
        // c = 1
        } else {
            // c = 0
            break;
        }
        i += 1;
    }
}

/// Convert `x` into base `q`, building a vector of length `n`.
fn as_base_q(x: u128, q: u16, n: usize) -> Vec<u16> {
    let ms = std::iter::repeat(q).take(n).collect_vec();
    as_mixed_radix(x, &ms)
}

/// Determine how many `mod q` digits fit into a `u128` (includes the color
/// digit).
pub fn digits_per_u128(modulus: u16) -> usize {
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

/// Convert `x` into base `q`.
pub fn as_base_q_u128(x: u128, q: u16) -> Vec<u16> {
    as_base_q(x, q, digits_per_u128(q))
}

/// Convert `x` into mixed radix form using the provided `radii`.
pub fn as_mixed_radix(x: u128, radii: &[u16]) -> Vec<u16> {
    let mut x = x;
    radii
        .iter()
        .map(|&m| {
            if x >= m as u128 {
                let d = x % m as u128;
                x = (x - d) / m as u128;
                d as u16
            } else {
                let d = x as u16;
                x = 0;
                d
            }
        })
        .collect()
}

/// Convert little-endian base `q` digits into `u128`.
pub fn from_base_q(ds: &[u16], q: u16) -> u128 {
    let mut x = 0u128;
    for &d in ds.iter().rev() {
        let (xp, overflow) = x.overflowing_mul(q.into());
        debug_assert!(!overflow, "overflow!!!! x={}", x);
        x = xp + d as u128;
    }
    x
}

/// Convert little-endian mixed radix digits into u128.
pub fn from_mixed_radix(digits: &[u16], radii: &[u16]) -> u128 {
    let mut x: u128 = 0;
    for (&d, &q) in digits.iter().zip(radii.iter()).rev() {
        let (xp, overflow) = x.overflowing_mul(q as u128);
        debug_assert!(!overflow, "overflow!!!! x={}", x);
        x = xp + d as u128;
    }
    x
}

////////////////////////////////////////////////////////////////////////////////
// bits

/// Get the bits of a u128 encoded in 128 u16s, which is convenient for the rest of
/// the library, which uses u16 as the base digit type in Wire.
pub fn u128_to_bits(x: u128, n: usize) -> Vec<u16> {
    let mut bits = Vec::with_capacity(n);
    let mut y = x;
    for _ in 0..n {
        let b = y & 1;
        bits.push(b as u16);
        y -= b;
        y /= 2;
    }
    bits
}

/// Convert into a u128 from the "bits" as u16. Assumes each "bit" is 0 or 1.
pub fn u128_from_bits(bs: &[u16]) -> u128 {
    let mut x = 0;
    for &b in bs.iter().skip(1).rev() {
        x += b as u128;
        x *= 2;
    }
    x += bs[0] as u128;
    x
}

////////////////////////////////////////////////////////////////////////////////
// primes & crt

/// Factor using the primes in the global `PRIMES` array. Fancy garbling only supports
/// composites with small prime factors.
///
/// We are limited by the size of the digits in Wire, and besides, if need large moduli,
/// you should use BundleGadgets and save.
pub fn factor(inp: u128) -> Vec<u16> {
    let mut x = inp;
    let mut fs = Vec::new();
    for &p in PRIMES.iter() {
        let q = p as u128;
        if x % q == 0 {
            fs.push(p);
            x /= q;
        }
    }
    if x != 1 {
        panic!("can only factor numbers with unique prime factors");
    }
    fs
}

/// Compute the CRT representation of x with respect to the primes ps.
pub fn crt(x: u128, ps: &[u16]) -> Vec<u16> {
    ps.iter().map(|&p| (x % p as u128) as u16).collect()
}

/// Compute the CRT representation of `x` with respect to the factorization of
/// `q`.
pub fn crt_factor(x: u128, q: u128) -> Vec<u16> {
    crt(x, &factor(q))
}

/// Compute the value x given a list of CRT primes and residues.
pub fn crt_inv(xs: &[u16], ps: &[u16]) -> u128 {
    let mut ret = 0;
    let M = ps.iter().fold(1, |acc, &x| x as i128 * acc);
    for (&p, &a) in ps.iter().zip(xs.iter()) {
        let p = p as i128;
        let q = M / p;
        ret += a as i128 * inv(q, p) * q;
        ret %= &M;
    }
    ret as u128
}

/// Compute the value `x` given a composite CRT modulus provided by `xs`.
pub fn crt_inv_factor(xs: &[u16], q: u128) -> u128 {
    crt_inv(xs, &factor(q))
}

/// Invert inp_a mod inp_b.
pub fn inv(inp_a: i128, inp_b: i128) -> i128 {
    let mut a = inp_a;
    let mut b = inp_b;
    let mut q;
    let mut tmp;

    let (mut x0, mut x1) = (0, 1);

    if b == 1 {
        return 1;
    }

    while a > 1 {
        q = a / b;

        // a, b = b, a%b
        tmp = b;
        b = a % b;
        a = tmp;

        tmp = x0;
        x0 = x1 - q * x0;
        x1 = tmp;
    }

    if x1 < 0 {
        x1 += inp_b;
    }

    x1
}

/// Number of primes supported by our library.
pub const NPRIMES: usize = 29;

/// Primes used in fancy garbling.
pub const PRIMES: [u16; 29] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109,
];

/// Primes skipping the modulus 2, which allows certain gadgets.
// pub const PRIMES_SKIP_2: [u16; 29] = [
//     3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
//     101, 103, 107, 109, 113,
// ];

/// Generate a CRT modulus with n primes.
pub fn modulus_with_nprimes(n: usize) -> u128 {
    product(&PRIMES[0..n])
}

/// Generate a CRT modulus that support at least n-bit integers, using the built-in
/// PRIMES.
pub fn modulus_with_width(n: u32) -> u128 {
    base_modulus_with_width(n, &PRIMES)
}

/// Generate the factors of a CRT modulus that support at least n-bit integers, using the
/// built-in PRIMES.
pub fn primes_with_width(n: u32) -> Vec<u16> {
    base_primes_with_width(n, &PRIMES)
}

/// Generate a CRT modulus that support at least n-bit integers, using provided primes.
pub fn base_modulus_with_width(nbits: u32, primes: &[u16]) -> u128 {
    product(&base_primes_with_width(nbits, primes))
}

/// Generate the factors of a CRT modulus that support at least n-bit integers, using provided primes.
pub fn base_primes_with_width(nbits: u32, primes: &[u16]) -> Vec<u16> {
    let mut res = 1;
    let mut ps = Vec::new();
    for &p in primes.iter() {
        res *= u128::from(p);
        ps.push(p);
        if (res >> nbits) > 0 {
            break;
        }
    }
    assert!((res >> nbits) > 0, "not enough primes!");
    ps
}

/// Generate a CRT modulus that support at least n-bit integers, using the built-in
/// PRIMES_SKIP_2 (does not include 2 as a factor).
// pub fn modulus_with_width_skip2(nbits: u32) -> u128 {
//     base_modulus_with_width(nbits, &PRIMES_SKIP_2)
// }

/// Compute the product of some u16s as a u128.
pub fn product(xs: &[u16]) -> u128 {
    xs.iter().fold(1, |acc, &x| acc * x as u128)
}

/// Raise a u16 to a power mod some value.
// pub fn powm(inp: u16, pow: u16, modulus: u16) -> u16 {
//     let mut x = inp as u16;
//     let mut z = 1;
//     let mut n = pow;
//     while n > 0 {
//         if n % 2 == 0 {
//             x = x.pow(2) % modulus as u16;
//             n /= 2;
//         } else {
//             z = x * z % modulus as u16;
//             n -= 1;
//         }
//     }
//     z as u16
// }

/// Returns `true` if `x` is a power of 2.
pub fn is_power_of_2(x: u16) -> bool {
    (x & (x - 1)) == 0
}

/// Generate deltas ahead of time for the Garbler.
pub fn generate_deltas<Wire: WireLabel>(primes: &[u16]) -> HashMap<u16, Wire> {
    let mut deltas = HashMap::new();
    let mut rng = rand::thread_rng();
    for q in primes {
        deltas.insert(*q, Wire::rand_delta(&mut rng, *q));
    }
    deltas
}

/// Extra Rng functionality, useful for `fancy-garbling`.
pub trait RngExt: rand::Rng + Sized {
    /// Randomly generate a `bool`.
    fn gen_bool(&mut self) -> bool {
        self.gen()
    }
    /// Randomly generate a `u16`.
    fn gen_u16(&mut self) -> u16 {
        self.gen()
    }
    /// Randomly generate a `u32`.
    fn gen_u32(&mut self) -> u32 {
        self.gen()
    }
    /// Randomly generate a `u64`.
    fn gen_u64(&mut self) -> u64 {
        self.gen()
    }
    /// Randomly generate a `usize`.
    fn gen_usize(&mut self) -> usize {
        self.gen()
    }
    /// Randomly generate a `u128`.
    fn gen_u128(&mut self) -> u128 {
        self.gen()
    }
    /// Randomly generate a `Block`.
    fn gen_block(&mut self) -> Block {
        self.gen()
    }
    /// Randomly generate a valid `Block`.
    fn gen_usable_block(&mut self, modulus: u16) -> Block {
        if is_power_of_2(modulus) {
            let nbits = (modulus - 1).count_ones();
            if 128 % nbits == 0 {
                return Block::from(self.gen_u128());
            }
        }
        let n = digits_per_u128(modulus);
        let max = (modulus as u128).pow(n as u32);
        Block::from(self.gen_u128() % max)
    }
    /// Randomly generate a prime (among the set of supported primes).
    fn gen_prime(&mut self) -> u16 {
        PRIMES[self.gen::<usize>() % NPRIMES]
    }
    /// Randomly generate a (supported) modulus.
    fn gen_modulus(&mut self) -> u16 {
        2 + (self.gen::<u16>() % 111)
    }
    /// Randomly generate a valid composite modulus.
    fn gen_usable_composite_modulus(&mut self) -> u128 {
        product(&self.gen_usable_factors())
    }
    /// Randomly generate a vector of valid factor
    fn gen_usable_factors(&mut self) -> Vec<u16> {
        let mut x: u128 = 1;
        PRIMES[..25]
            .iter()
            .cloned()
            .filter(|_| self.gen()) // randomly take this prime
            .take_while(|&q| {
                // make sure that we don't overflow!
                match x.checked_mul(q as u128) {
                    None => false,
                    Some(y) => {
                        x = y;
                        true
                    }
                }
            })
            .collect()
    }
}

impl<R: rand::Rng + Sized> RngExt for R {}

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::RngExt;
    use rand::thread_rng;

    #[test]
    fn crt_conversion() {
        let mut rng = thread_rng();
        let ps = &PRIMES[..25];
        let modulus = product(ps);

        for _ in 0..128 {
            let x = rng.gen_u128() % modulus;
            assert_eq!(crt_inv(&crt(x, ps), ps), x);
        }
    }

    #[test]
    fn factoring() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let mut ps = Vec::new();
            let mut q: u128 = 1;
            for &p in PRIMES.iter() {
                if rng.gen_bool() {
                    match q.checked_mul(p as u128) {
                        None => break,
                        Some(z) => q = z,
                    }
                    ps.push(p);
                }
            }
            assert_eq!(factor(q), ps);
        }
    }

    #[test]
    fn bits() {
        let mut rng = thread_rng();
        for _ in 0..128 {
            let x = rng.gen_u128();
            assert_eq!(u128_from_bits(&u128_to_bits(x, 128)), x);
        }
    }

    #[test]
    fn base_q_conversion() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = 2 + (rng.gen_u16() % 111);
            let x = u128::from(rng.gen_usable_block(q));
            let y = as_base_q(x, q, digits_per_u128(q));
            let z = from_base_q(&y, q);
            assert_eq!(x, z);
        }
    }
}
