mod receiver;
mod sender;

use itertools::Itertools;
use rand::RngCore;

use receiver::Receiver;
use sender::Sender;

use scuttlebutt::Block;

const NUM_HASHES: usize = 3;

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

#[inline(always)]
pub fn combine_buckets<const N: usize>(
    x: usize,
    len: usize,
    buckets: &Buckets,
    elems: &[[Block; N]],
) -> Block {
    let mut hx: [usize; NUM_HASHES] = [
        HASHES[0].hash_idx(x, len),
        HASHES[1].hash_idx(x, len),
        HASHES[2].hash_idx(x, len),
    ];
    hx.sort();
    let mut rx: Block = Default::default();
    for hix in hx.iter().copied().dedup() {
        rx ^= elems[hix][buckets.pos(hix, x)];
    }
    rx
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
    pub const fn hash_idx(&self, v: usize, len: usize) -> usize {
        (self.hash(v as u32) % (len as u32)) as usize
    }
}

/// Pre-compute the bucket sorting
#[derive(Debug)]
pub struct Buckets {
    max: usize,
    buckets: Vec<Vec<usize>>,
}

impl Buckets {
    pub fn build(n: usize, m: usize) -> Self {
        // compute sorted buckets
        let mut buckets: Vec<Vec<usize>> = vec![vec![]; m as usize];
        for x in 0..n {
            for hsh in HASHES.iter() {
                let j = hsh.hash_idx(x, m);
                buckets[j].push(x);
            }
        }

        let mut max: usize = 0;
        for bucket in buckets.iter_mut() {
            // remove duplicates
            // (same key could hash to the same bucket under different hash functions)
            bucket.dedup();

            // compute the maximum size of any bucket (for sanity checking)
            if bucket.len() > max {
                max = bucket.len();
            }
        }

        Self { buckets, max }
    }

    fn pos(&self, j: usize, x: usize) -> usize {
        // TODO: use binary search
        // (or convert to hash-map)
        for (i, e) in self.buckets[j].iter().copied().enumerate() {
            if e == x {
                return i;
            }
        }
        unreachable!("Lookup of element not in bucket")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            cache::{CachedReceiver, CachedSender},
            spcot,
            util::unique_random_array,
            CSP,
        },
        *,
    };

    use crate::ot::{
        FixedKeyInitializer,
        KosDeltaReceiver,
        KosDeltaSender,
        Receiver as OtReceiver,
    };

    use lazy_static::lazy_static;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use scuttlebutt::{channel::unix_channel_pair, Block};
    use std::thread::spawn;

    const TEST_T: usize = 5;
    const TEST_N: usize = 10;
    const TEST_M: usize = (TEST_T * 3) / 2;
    const TEST_BUCKET_LOG_SIZE: usize = 3;
    const TEST_BUCKET_SIZE: usize = 1 << TEST_BUCKET_LOG_SIZE;

    lazy_static! {
        static ref TEST_BUCKETS: Buckets = Buckets::build(TEST_N, TEST_M);
    }

    #[test]
    fn test_mpcot_correlation() {
        let mut root = StdRng::seed_from_u64(0x5367_FA32_72B1_8478);

        for _ in 0..5 {
            let mut rng1 = StdRng::seed_from_u64(root.gen());
            let mut rng2 = StdRng::seed_from_u64(root.gen());
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
                >(&TEST_BUCKETS, &mut cache, &mut spcot, &mut c2, &mut rng2)
                .unwrap();

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
            let w = Receiver::extend::<
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

            let (delta, mut v) = handle.join().unwrap();

            println!("before: v = {:?}, w = {:?}", v, w);

            // check correlation
            for i in alpha.iter().copied() {
                v[i] ^= delta;
            }
            debug_assert_eq!(v, w, "alpha = {:?}", alpha);
        }
    }
}
