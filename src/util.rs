//! Tools useful for interacting with `fancy-garbling`.

use itertools::Itertools;
use num::bigint::BigInt;
use num::integer::Integer;
use num::{ToPrimitive, Zero, One, Signed};

////////////////////////////////////////////////////////////////////////////////
// mixed radix stuff

pub fn base_q_add(xs: &[u16], ys: &[u16], q: u16) -> Vec<u16> {
    if ys.len() > xs.len() {
        return base_q_add(ys, xs, q);
    }
    let mut ret = xs.to_vec();
    base_q_add_eq(&mut ret, ys, q);
    ret
}

pub fn base_q_add_eq(xs: &mut [u16], ys: &[u16], q: u16)
{
    debug_assert!(
        xs.len() >= ys.len(),
        "q={} xs.len()={} ys.len()={} xs={:?} ys={:?}",
        q, xs.len(), ys.len(), xs, ys
    );

    let mut c = 0;
    let mut i = 0;

    while i < ys.len() {
        xs[i] += ys[i] + c;
        c = 0;
        if xs[i] >= q {
            xs[i] -= q;
            c = 1;
        }
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

pub fn as_base_q(x: u128, q: u16, n: usize) -> Vec<u16> {
    let ms = std::iter::repeat(q).take(n).collect_vec();
    as_mixed_radix(x, &ms)
}

pub fn digits_per_u128(modulus: u16) -> usize {
    (128.0 / (modulus as f64).log2().ceil()).floor() as usize
}

pub fn as_base_q_u128(x: u128, q: u16) -> Vec<u16> {
    as_base_q(x, q, digits_per_u128(q))
}

pub fn as_mixed_radix(x: u128, ms: &[u16]) -> Vec<u16> {
    let mut x = x;
    ms.iter().map(|&m| {
        if x >= m as u128 {
            let d = x % m as u128;
            x = (x - d) / m as u128;
            d as u16
        } else {
            let d = x as u16;
            x = 0;
            d
        }
    }).collect()
}

pub fn from_base_q(ds: &[u16], q: u16) -> u128 {
    let mut x: u128 = 0;
    for &d in ds.iter().rev() {
        let (xp,overflow) = x.overflowing_mul(q as u128);
        debug_assert_eq!(overflow, false, "overflow!!!! x={}", x);
        x = xp + d as u128;
    }
    x
}

pub fn from_mixed_radix(ds: &[u16], qs: &[u16]) -> u128 {
    let mut x: u128 = 0;
    for (&d,&q) in ds.iter().zip(qs.iter()).rev() {
        let (xp,overflow) = x.overflowing_mul(q as u128);
        debug_assert_eq!(overflow, false, "overflow!!!! x={}", x);
        x = xp + d as u128;
    }
    x
}

////////////////////////////////////////////////////////////////////////////////
// bits

/// Get the bits of a `u128` encoded in 128 `u16`s, which is convenient for the rest of
/// the library, which uses `u16` as the base digit type in `Wire`.
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

pub fn u128_from_bits(bs: &[u16]) -> u128 {
    let mut x = 0;
    for &b in bs.iter().skip(1).rev() {
        x += b as u128;
        x *= 2;
    }
    x += bs[0] as u128;
    x
}

pub fn u128_to_bytes(x: u128) -> [u8;16] {
    unsafe {
        std::mem::transmute(x)
    }
}

pub fn bytes_to_u128(bytes: [u8;16]) -> u128 {
    unsafe {
        std::mem::transmute(bytes)
    }
}

////////////////////////////////////////////////////////////////////////////////
// primes & crt

/// Factor using the primes in the global `PRIMES` array. We only support composites with
/// small prime factors in the high-level circuit representation.
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

/// Compute the CRT representation of `x` with respect to the primes `ps`.
pub fn crt(ps: &[u16], x: u128) -> Vec<u16> {
    ps.iter().map(|&p| {
        (x % p as u128) as u16
    }).collect()
}

/// Compute the CRT representation of `x` with respect to the factorization of `q`.
pub fn crt_factor(x: u128, q: u128) -> Vec<u16> {
    crt(&factor(q), x)
}

/// Compute the value `x` given a list of CRT primes and residues.
pub fn crt_inv(ps: &[u16], xs: &[u16]) -> u128 {
    let mut ret = BigInt::zero();
    let M = ps.iter().fold(BigInt::one(), |acc, &x| BigInt::from(x) * acc );
    for (&p, &a) in ps.iter().zip(xs.iter()) {
        let p = BigInt::from(p);
        let q = &M / &p;
        ret += BigInt::from(a) * inv_ref(&q,&p) * q;
        ret %= &M;
    }
    ret.to_u128().unwrap()
}

pub fn crt_inv_factor(xs: &[u16], q: u128) -> u128 {
    crt_inv(&factor(q), xs)
}

/// Generic algorithm to invert `inp_a` mod `inp_b`. As ref so as to support `BigInt`
/// without copying.
pub fn inv_ref<T: Clone + Integer + Signed>(inp_a: &T, inp_b: &T) -> T {
    let mut a = inp_a.clone();
    let mut b = inp_b.clone();
    let mut q;
    let mut tmp;

    let (mut x0, mut x1) = (T::zero(), T::one());

    if b == T::one() {
        return T::one();
    }

    while a > T::one() {
        q = a.clone() / b.clone();

        // a, b = b, a%b
        tmp = b.clone();
        b = a.clone() % b.clone();
        a = tmp;

        tmp = x0.clone();
        x0 = x1.clone() - q.clone() * x0.clone();
        x1 = tmp.clone();
    }

    if x1 < T::zero() {
        x1 = x1 + inp_b.clone();
    }

    x1
}

/// Invert `a` mod `m`.
pub fn inv<T: Copy + Integer + Signed>(a: T, m: T) -> T {
    inv_ref(&a, &m)
}

/// Number of primes supported by our library.
pub const NPRIMES: usize = 29;

/// Primes used by `fancy-garbling`.
pub const PRIMES: [u16;29] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109
];

/// Primes skipping the modulus 2, which allows certain gadgets in `circuit::crt`.
pub const PRIMES_SKIP_2: [u16;29] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113
];

pub fn modulus_with_width(nbits: u32) -> u128 {
    base_modulus_with_width(nbits, &PRIMES)
}

pub fn base_modulus_with_width(nbits: u32, ps: &[u16]) -> u128 {
    let mut res = 1;
    let mut i = 0;
    loop {
        res *= u128::from(ps[i]);
        if (res >> nbits) > 0 {
            break;
        }
        i += 1;
        debug_assert!(i < ps.len());
    }
    res
}

pub fn modulus_with_width_skip2(nbits: u32) -> u128 {
    base_modulus_with_width(nbits, &PRIMES_SKIP_2)
}

pub fn product(xs: &[u16]) -> u128 {
    xs.iter().fold(1, |acc, &x| acc * x as u128)
}

pub fn powm(inp: u16, pow: u16, modulus: u16) -> u16 {
    let mut x = inp as u16;
    let mut z = 1;
    let mut n = pow;
    while n > 0 {
        if n % 2 == 0 {
            x = x.pow(2) % modulus as u16;
            n /= 2;
        } else {
            z = x * z % modulus as u16;
            n -= 1;
        }
    }
    z as u16
}

pub fn is_power_of_2<I>(x: I) -> bool
    where I: std::ops::Sub<Output=I> + std::ops::BitAnd<Output=I> +
             num::Zero + num::One + std::cmp::PartialEq + Clone
{
    (x.clone() & (x - I::one())) == I::zero()
}

/// Extra Rng functionality, useful for `fancy-garbling`.
pub trait RngExt : rand::Rng + Sized {
    fn gen_bool(&mut self) -> bool { self.gen() }
    fn gen_u16(&mut self) -> u16 { self.gen() }
    fn gen_u32(&mut self) -> u32 { self.gen() }
    fn gen_u64(&mut self) -> u16 { self.gen() }
    fn gen_usize(&mut self) -> usize { self.gen() }
    fn gen_u128(&mut self) -> u128 { self.gen() }

    fn gen_usable_u128(&mut self, modulus: u16) -> u128 {
        if is_power_of_2(modulus) {
            let nbits = (modulus-1).count_ones();
            if 128 % nbits == 0 {
                return self.gen_u128();
            }
        }
        let n = digits_per_u128(modulus);
        let max = (modulus as u128).pow(n as u32);
        self.gen_u128() % max
    }

    fn gen_prime(&mut self) -> u16 {
        PRIMES[self.gen::<usize>() % NPRIMES]
    }

    fn gen_modulus(&mut self) -> u16 {
        2 + (self.gen::<u16>() % 111)
    }

    fn gen_usable_composite_modulus(&mut self) -> u128 {
        product(&self.gen_usable_factors())
    }

    fn gen_usable_factors(&mut self) -> Vec<u16> {
        let mut x: u128 = 1;
        PRIMES.iter().cloned()
            .filter(|_| self.gen()) // randomly take this prime
            .take_while(|&q| { // make sure that we don't overflow!
                match x.checked_mul(q as u128) {
                    None => false,
                    Some(y) => {
                        x = y;
                        true
                    },
                }
            }).collect()
    }
}

impl<R: rand::Rng + Sized> RngExt for R { }

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
            assert_eq!(crt_inv(ps, &crt(ps, x)), x);
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
            let x = rng.gen_usable_u128(q);
            let y = as_base_q(x, q, digits_per_u128(q));
            let z = from_base_q(&y, q);
            assert_eq!(x, z);
        }
    }

    #[test]
    fn base_q_addition() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = 2 + (rng.gen_u16() % 111);
            let n = digits_per_u128(q) - 2;
            println!("q={} n={}", q, n);
            let Q = (q as u128).pow(n as u32);

            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;

            let xp = as_base_q(x,q,n);
            let yp = as_base_q(y,q,n);

            let zp = base_q_add(&xp, &yp, q);

            let z = from_base_q(&zp, q);

            assert_eq!((x+y) % Q, z);
        }
    }
}
