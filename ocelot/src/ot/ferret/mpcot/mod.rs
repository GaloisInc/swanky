mod receiver;
mod sender;

use lazy_static::lazy_static;
use rand::RngCore;

const NUM_HASHES: usize = 3;

const SETUP_K: usize = 37_248;
const SETUP_N: usize = 616_092;
const SETUP_T: usize = 1_254;
const SETUP_M: usize = (SETUP_T * 3) / 2;
const SETUP_BUCKET_LOG_SIZE: usize = 11;

const MAIN_K: usize = 588_160;
const MAIN_N: usize = 10_616_092;
const MAIN_T: usize = 1_324;
const MAIN_M: usize = (MAIN_T * 3) / 2;
const MAIN_BUCKET_LOG_SIZE: usize = 14;

const CUCKOO_ITERS: usize = 100;

/// Largest 32-bit prime
const P: u64 = 0xffff_fffb;

/// Chosen by fair dice-roll, guaranteed to be random.
pub const HASHES: [UH; NUM_HASHES] = [
    UH::new(0x5fd8e413, 0x830da067),
    UH::new(0xb5dc3a1f, 0x84ec3ea6),
    UH::new(0x23ecfe4a, 0xfb543bcf),
];

/// 2-Universal Hash Function with 32-bit (co)-domain
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UH {
    a: u64,
    b: u64,
}

impl UH {
    pub fn gen<R: RngCore>(rng: &mut R) -> Self {
        UH {
            a: rng.next_u32() as u64,
            b: rng.next_u32() as u64,
        }
    }

    pub const fn new(a: u32, b: u32) -> Self {
        UH {
            a: a as u64,
            b: b as u64,
        }
    }

    #[inline(always)]
    pub const fn hash(&self, v: u32) -> u32 {
        let v: u64 = v as u64;
        let m = (v * self.a + self.b) % P;
        m as u32
    }

    #[inline(always)]
    pub const fn hash_mod(&self, v: u32, m: u32) -> u32 {
        self.hash(v) % m
    }
}

/// Pre-compute the bucket sorting
pub struct Buckets {
    max: usize,
    buckets: Vec<Vec<u32>>,
}

impl Buckets {
    fn build(n: u32, m: u32) -> Self {
        // compute sorted buckets
        let mut buckets: Vec<Vec<u32>> = vec![vec![]; m as usize];
        for x in 0..n {
            for hsh in HASHES.iter() {
                let j = hsh.hash(x as u32) % m;
                buckets[j as usize].push(x);
            }
        }

        // compute the maximum size of any bucket
        let mut max: usize = 0;
        for bucket in buckets.iter() {
            if bucket.len() > max {
                max = bucket.len();
            }
        }

        Self { buckets, max }
    }

    fn pos(&self, j: usize, x: u32) -> usize {
        for (i, e) in self.buckets[j].iter().copied().enumerate() {
            if e == x {
                return i;
            }
        }
        unreachable!("Lookup of element not in bucket")
    }
}

lazy_static! {
    static ref BUCKETS_SETUP: Buckets = Buckets::build(SETUP_N as u32, SETUP_M as u32);
    static ref BUCKETS_MAIN: Buckets = Buckets::build(MAIN_N as u32, MAIN_M as u32);
}

#[test]
fn test_bucket_size() {
    assert!(BUCKETS_SETUP.max < 1 << SETUP_BUCKET_LOG_SIZE);
    assert!(BUCKETS_MAIN.max < 1 << MAIN_BUCKET_LOG_SIZE);
}
