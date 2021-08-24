use crate::{
    errors::Error,
    ot::ferret::{cache::CachedReceiver, spcot::Receiver as SPCOTReceiver},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

use std::mem;

use super::{combine_buckets, Buckets, CUCKOO_ITERS, HASHES};

pub struct Receiver {}

impl Receiver {
    pub fn extend_reg<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const T: usize,
        const N: usize,
        const LOG_SPLEN: usize,
        const SPLEN: usize,
    >(
        cache: &mut CachedReceiver, // bag of base-COT
        spcot: &mut SPCOTReceiver,  // SPCOT implementation
        channel: &mut C,            // communication channel
        rng: &mut R,                // cryptographically secure RNG
        alphas: &[usize; T],        // 1-positions in each SPLEN sized chunk
    ) -> Result<Vec<Block>, Error> {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(T * SPLEN, N);
            for i in alphas.iter().copied() {
                debug_assert!(i < SPLEN);
            }
        }

        let r: Vec<[Block; SPLEN]> =
            spcot.extend::<_, _, LOG_SPLEN, SPLEN>(cache, channel, rng, &alphas[..])?;

        // view the Vec<[BLOCK; SPLEN]> as a flat Vec<Block>
        let r: Vec<Block> = unsafe {
            let mut v = mem::ManuallyDrop::new(r);
            debug_assert_eq!(v.len(), alphas.len());
            debug_assert_eq!(v.len() * SPLEN, N);
            let p = v.as_mut_ptr();
            let cap = v.capacity();
            Vec::from_raw_parts(p as *mut Block, N, cap * SPLEN)
        };
        debug_assert_eq!(r.len(), N);
        Ok(r)
    }

    pub fn extend<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const T: usize,
        const N: usize,
        const M: usize,
        const LOG_SIZE_BUCKET: usize,
        const SIZE_BUCKET: usize,
    >(
        buckets: &Buckets,          // precomputed bucket lookup
        cache: &mut CachedReceiver, // bag of base-COT
        spcot: &mut SPCOTReceiver,  // SPCOT implementation
        channel: &mut C,            // communication channel
        rng: &mut R,                // cryptographically secure RNG
        alphas: &[usize; T],        // 1-positions
    ) -> Result<Vec<Block>, Error> {
        let last_bucket: usize = (1 << LOG_SIZE_BUCKET) - 1;

        #[cfg(debug_assertions)]
        {
            debug_assert!(buckets.max < 1 << LOG_SIZE_BUCKET);
            debug_assert_eq!(SIZE_BUCKET, 1 << LOG_SIZE_BUCKET);

            // check that all alpha's are unique
            let mut alphas_sorted = *alphas;
            alphas_sorted.sort();
            for i in 0..(T - 1) {
                debug_assert_ne!(alphas_sorted[i], alphas_sorted[i + 1]);
                debug_assert!(alphas_sorted[i] < N);
            }
        }

        // insert alpha's into Cuckoo table
        let mut table: Vec<Option<usize>> = vec![None; M];
        for mut alpha in alphas.iter().copied() {
            'cuckoo: for iter in 0..CUCKOO_ITERS {
                // try every hash
                for h in HASHES.iter() {
                    let i = h.hash_idx(alpha, M);
                    let e = &mut table[i];
                    if e.is_none() {
                        *e = Some(alpha);
                        break 'cuckoo;
                    }
                }

                // push out
                let i = HASHES[rng.gen::<usize>() % HASHES.len()].hash_idx(alpha, M);
                alpha = mem::replace(&mut table[i], Some(alpha)).unwrap();
                assert!(iter < CUCKOO_ITERS - 1);
            }
        }

        // compute the indexes in each bucket to retrieve
        let p: Vec<usize> = table
            .into_iter()
            .enumerate()
            .map(|(j, e)| match e {
                None => last_bucket,
                Some(alpha) => buckets.pos(j, alpha).unwrap(),
            })
            .collect();
        debug_assert_eq!(p.len(), M);

        // run M calls to SPCOT in parallel
        let rh = spcot.extend::<_, _, LOG_SIZE_BUCKET, SIZE_BUCKET>(cache, channel, rng, &p[..])?;
        debug_assert_eq!(rh.len(), M);

        // r[x] := \sum_{i} rh[h_i(x)][pos_(h_i(x))(x)]
        let mut r: Vec<Block> = Vec::with_capacity(N);
        for x in 0..N {
            r.push(combine_buckets(x, M, buckets, &rh[..]));
        }
        Ok(r)
    }
}
