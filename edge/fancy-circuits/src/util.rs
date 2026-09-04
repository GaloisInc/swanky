//! Utility functions.
//!
//! Note: all number representations are little-endian.

use rand::RngExt as _;

use crate::CrtBundle;
use fancy_traits::HasModulus;

/// Convert a `u128` into a vector of bits.
pub(crate) fn u128_to_bits(x: u128, nbits: usize) -> Vec<u16> {
    let mut bits = Vec::with_capacity(nbits);
    let mut y = x;
    for _ in 0..nbits {
        let b = y & 1;
        bits.push(b as u16);
        y -= b;
        y /= 2;
    }
    bits
}

/// Convert a vector of bits into a `u128`.
///
/// # Panics
/// This panics if any element in the vector is non-binary.
pub fn u128_from_bits(bs: &[u16]) -> u128 {
    let mut x = 0;
    for &b in bs.iter().skip(1).rev() {
        assert!(b == 0 || b == 1);
        x += b as u128;
        x *= 2;
    }
    x += bs[0] as u128;
    x
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

const NPRIMES: usize = 29;

/// Supported primes.
pub const PRIMES: [u16; NPRIMES] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109,
];

/// Factor using the primes in the [`PRIMES`] array.
pub fn factor(inp: u128) -> Vec<u16> {
    let mut x = inp;
    let mut fs = Vec::new();
    for &p in PRIMES.iter() {
        let q = p as u128;
        if x.is_multiple_of(q) {
            fs.push(p);
            x /= q;
        }
    }
    if x != 1 {
        panic!("can only factor numbers with unique prime factors");
    }
    fs
}

/// Compute the CRT representation of `x` with respect to the primes `ps`.
pub fn crt(x: u128, ps: &[u16]) -> Vec<u16> {
    ps.iter().map(|&p| (x % p as u128) as u16).collect()
}

/// Compute the value `x` given a list of CRT primes.
pub fn crt_inv(xs: &[u16], ps: &[u16]) -> u128 {
    let mut ret = 0;
    let m: i128 = ps.iter().fold(1, |acc, &x| x as i128 * acc);
    for (&p, &a) in ps.iter().zip(xs.iter()) {
        let p = p as i128;
        let q = m / p;
        ret += a as i128 * inv(q, p) * q;
        ret %= &m;
    }
    ret as u128
}

/// Compute the value given a composite CRT modulus provided by `xs`.
pub fn crt_inv_factor(xs: &[u16], q: u128) -> u128 {
    crt_inv(xs, &factor(q))
}

/// Invert `x mod y`.
pub(crate) fn inv(x: i128, y: i128) -> i128 {
    let mut a = x;
    let mut b = y;
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
        x1 += y;
    }

    x1
}

/// Compute the product of some `u16`s as a `u128`.
pub fn product(xs: &[u16]) -> u128 {
    xs.iter().fold(1, |acc, &x| acc * x as u128)
}

/// Generate a CRT modulus that support at least `n`-bit integers, using
/// [`PRIMES`].
pub fn modulus_with_width(n: usize) -> u128 {
    product(&base_primes_with_width(n, &PRIMES))
}

/// Generate the factors of a CRT modulus that support at least `n`-bit
/// integers, using [`PRIMES`].
pub fn primes_with_width(n: usize) -> Vec<u16> {
    base_primes_with_width(n, &PRIMES)
}

/// Generate the factors of a CRT modulus that support at least `n`-bit integers,
/// using provided primes.
fn base_primes_with_width(nbits: usize, primes: &[u16]) -> Vec<u16> {
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

/// Compute the `ms` needed for the number of CRT primes in `x`, with accuracy
/// `accuracy`.
///
/// Supported accuracy: ["100%", "99.9%", "99%"]
pub(crate) fn get_ms<W: Clone + HasModulus>(x: &CrtBundle<W>, accuracy: &str) -> Vec<u16> {
    match accuracy {
        "100%" => match x.moduli().len() {
            3 => vec![2; 5],
            4 => vec![3, 26],
            5 => vec![3, 4, 54],
            6 => vec![5, 5, 5, 60],
            7 => vec![5, 6, 6, 7, 86],
            8 => vec![5, 7, 8, 8, 9, 98],
            9 => vec![5, 5, 7, 7, 7, 7, 7, 76],
            10 => vec![5, 5, 6, 6, 6, 6, 11, 11, 202],
            11 => vec![5, 5, 5, 5, 5, 6, 6, 6, 7, 7, 8, 150],
            n => panic!("unknown exact Ms for {} primes!", n),
        },
        "99.999%" => match x.moduli().len() {
            8 => vec![5, 5, 6, 7, 102],
            9 => vec![5, 5, 6, 7, 114],
            10 => vec![5, 6, 6, 7, 102],
            11 => vec![5, 5, 6, 7, 130],
            n => panic!("unknown 99.999% accurate Ms for {} primes!", n),
        },
        "99.99%" => match x.moduli().len() {
            6 => vec![5, 5, 5, 42],
            7 => vec![4, 5, 6, 88],
            8 => vec![4, 5, 7, 78],
            9 => vec![5, 5, 6, 84],
            10 => vec![4, 5, 6, 112],
            11 => vec![7, 11, 174],
            n => panic!("unknown 99.99% accurate Ms for {} primes!", n),
        },
        "99.9%" => match x.moduli().len() {
            5 => vec![3, 5, 30],
            6 => vec![4, 5, 48],
            7 => vec![4, 5, 60],
            8 => vec![3, 5, 78],
            9 => vec![9, 140],
            10 => vec![7, 190],
            n => panic!("unknown 99.9% accurate Ms for {} primes!", n),
        },
        "99%" => match x.moduli().len() {
            4 => vec![3, 18],
            5 => vec![3, 36],
            6 => vec![3, 40],
            7 => vec![3, 40],
            8 => vec![126],
            9 => vec![138],
            10 => vec![140],
            n => panic!("unknown 99% accurate Ms for {} primes!", n),
        },
        _ => panic!("get_ms: unsupported accuracy {}", accuracy),
    }
}

/// Extra [`rand::Rng`] functionality, useful for testing.
pub trait RngExt: rand::Rng + Sized {
    /// Randomly generate a prime (among the set of supported primes).
    fn gen_prime(&mut self) -> u16 {
        PRIMES[self.random_range(..NPRIMES)]
    }
    /// Randomly generate a (supported) modulus.
    fn gen_modulus(&mut self) -> u16 {
        2 + (self.random::<u16>() % 111)
    }
    /// Randomly generate a valid composite modulus.
    fn gen_usable_composite_modulus(&mut self) -> u128 {
        product(&self.gen_usable_factors())
    }
    /// Randomly generate a vector of valid factor.
    fn gen_usable_factors(&mut self) -> Vec<u16> {
        let mut x: u128 = 1;
        PRIMES[..25]
            .iter()
            .cloned()
            .filter(|_| self.random()) // randomly take this prime
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn crt_conversion() {
        let mut rng = rng();
        let ps = &PRIMES[..25];
        let modulus = product(ps);

        for _ in 0..128 {
            let x = rng.random::<u128>() % modulus;
            assert_eq!(crt_inv(&crt(x, ps), ps), x);
        }
    }

    #[test]
    fn factoring() {
        let mut rng = rng();
        for _ in 0..16 {
            let mut ps = Vec::new();
            let mut q: u128 = 1;
            for &p in PRIMES.iter() {
                if rng.random::<bool>() {
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
        let mut rng = rng();
        for _ in 0..128 {
            let x = rng.random::<u128>();
            assert_eq!(u128_from_bits(&u128_to_bits(x, 128)), x);
        }
    }
}
