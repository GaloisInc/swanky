use crate::{
    errors::Error,
    ot::ferret::{cache::CachedReceiver, spcot::Receiver as SPCOTReceiver},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

use std::mem;

use super::{combine_buckets, Buckets, CUCKOO_ITERS, HASHES};

pub(crate) struct Receiver {}

impl Receiver {
    pub(crate) fn extend<
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
                Some(alpha) => buckets.pos(j, alpha),
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
