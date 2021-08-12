mod receiver;
mod sender;

use lazy_static::lazy_static;
use rand::RngCore;

use receiver::Receiver;
use sender::Sender;

const NUM_HASHES: usize = 3;

const SETUP_K: usize = 37_248;
const SETUP_N: usize = 616_092;
const SETUP_T: usize = 1_254;
const SETUP_M: usize = (SETUP_T * 3) / 2;
const SETUP_BUCKET_LOG_SIZE: usize = 11;
const SETUP_BUCKET_SIZE: usize = 1 << SETUP_BUCKET_LOG_SIZE;

const MAIN_K: usize = 588_160;
const MAIN_N: usize = 10_616_092;
const MAIN_T: usize = 1_324;
const MAIN_M: usize = (MAIN_T * 3) / 2;
const MAIN_BUCKET_LOG_SIZE: usize = 14;
const MAIN_BUCKET_SIZE: usize = 1 << MAIN_BUCKET_LOG_SIZE;

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

mod tests {
    use super::*;

    use std::thread::spawn;

    use super::super::{
        cache::{CachedReceiver, CachedSender},
        spcot,
        util::unique_random_array,
        CSP,
    };

    use crate::ot::FixedKeyInitializer;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use scuttlebutt::{channel::unix_channel_pair, Aes128, AesHash, Block, F128};

    use simple_logger;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender, Receiver as OtReceiver};

    use std::convert::TryFrom;

    const TEST_T: usize = 3;
    const TEST_N: usize = 100;
    const TEST_M: usize = (TEST_T * 3) / 2;
    const TEST_BUCKET_LOG_SIZE: usize = 11;
    const TEST_BUCKET_SIZE: usize = 1 << TEST_BUCKET_LOG_SIZE;

    lazy_static! {
        static ref TEST_BUCKETS: Buckets = Buckets::build(TEST_N as u32, TEST_M as u32);
    }

    #[test]
    fn test_bucket_size() {
        assert!(BUCKETS_SETUP.max < SETUP_BUCKET_SIZE);
        assert!(BUCKETS_MAIN.max < MAIN_BUCKET_SIZE);
        assert!(TEST_BUCKETS.max < TEST_BUCKET_SIZE);
    }

    #[test]
    fn test_mpcot_correlation() {
        // de-randomize the test
        let mut rng1 = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        let mut rng2 = StdRng::seed_from_u64(0x8DEE_F32A_8712_321F);

        // let _ = simple_logger::init();
        let (mut c1, mut c2) = unix_channel_pair();

        let handle = spawn(move || {
            let delta: Block = rng2.gen();
            let mut cache: CachedSender = CachedSender::new(delta);

            // generate the required number of base OT
            let mut kos18 =
                KosDeltaSender::init_fixed_key(&mut c2, delta.into(), &mut rng2).unwrap();
            cache
                .generate(
                    &mut kos18,
                    &mut c2,
                    &mut rng2,
                    TEST_BUCKET_LOG_SIZE * TEST_M + CSP,
                )
                .unwrap();

            // create spcot functionality
            let mut spcot = spcot::Sender::init(delta);

            // do MPCOT extension
            let s = Sender::extend::<
                _,
                _,
                TEST_T,
                TEST_N,
                TEST_M,
                TEST_BUCKET_LOG_SIZE,
                TEST_BUCKET_SIZE,
            >(&TEST_BUCKETS, &mut cache, &mut spcot, &mut c2, &mut rng2);

            // sanity check: we consumed all the COTs
            assert_eq!(cache.capacity(), 0);
            (delta, s)
        });

        // generate a bunch of base COTs
        let mut cache: CachedReceiver = CachedReceiver::default();
        let mut kos18 = KosDeltaReceiver::init(&mut c1, &mut rng1).unwrap();
        cache
            .generate(
                &mut kos18,
                &mut c1,
                &mut rng1,
                TEST_BUCKET_LOG_SIZE * TEST_M + CSP,
            )
            .unwrap();

        // create spcot functionality
        let mut spcot = spcot::Receiver::init();

        // pick random indexes to set
        let alpha = unique_random_array(&mut rng1, TEST_N);

        // do MPCOT extension
        let r = Receiver::extend::<
            _,
            _,
            TEST_T,
            TEST_N,
            TEST_M,
            TEST_BUCKET_LOG_SIZE,
            TEST_BUCKET_SIZE,
        >(
            &TEST_BUCKETS,
            &mut cache,
            &mut spcot,
            &mut c1,
            &mut rng1,
            &alpha,
        )
        .unwrap();

        // sanity check: we consumed all the COTs
        assert_eq!(cache.capacity(), 0);

        let (delta, mut s) = handle.join().unwrap();
    }
}
