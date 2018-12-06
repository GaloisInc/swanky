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

////////////////////////////////////////////////////////////////////////////////
// primes & crt

// only factor using the above primes- we only support composites with small
// prime factors in the high-level circuit representation
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

pub fn crt(ps: &[u16], x: u128) -> Vec<u16> {
    ps.iter().map(|&p| {
        (x % p as u128) as u16
    }).collect()
}

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

pub fn inv<T: Copy + Integer + Signed>(a: T, m: T) -> T {
    inv_ref(&a, &m)
}

pub const NPRIMES: usize = 29;

pub const PRIMES: [u16;29] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109
];

pub const PRIMES_SKIP_2: [u16;29] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113
];

pub fn modulus_with_width(nbits: u32) -> u128 {
    base_modulus_with_width(nbits, &PRIMES)
}

pub fn modulus_with_width_skip2(nbits: u32) -> u128 {
    base_modulus_with_width(nbits, &PRIMES_SKIP_2)
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
