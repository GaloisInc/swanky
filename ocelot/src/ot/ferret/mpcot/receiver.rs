use crate::{
    errors::Error,
    ot::ferret::{cache::CachedReceiver, spcot::Receiver as SPCOTReceiver},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

use std::mem;

use super::{Buckets, CUCKOO_ITERS, HASHES};

struct Receiver {}

impl Receiver {
    fn extend<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const T: usize,
        const N: usize,
        const M: usize,
        const LOG_SIZE_BUCKET: usize,
        const SIZE_BUCKET: usize,
    >(
        bucket: &Buckets,           // precomputed bucket lookup
        cache: &mut CachedReceiver, // bag of base-COT
        spcot: &mut SPCOTReceiver,  // SPCOT implementation
        channel: &mut C,            // communication channel
        rng: &mut R,                // cryptographically secure RNG
        alphas: &[u32; T],          // 1-positions
    ) -> Result<Vec<Block>, Error> {
        let last_bucket: usize = (1 << LOG_SIZE_BUCKET) - 1;
        debug_assert!(bucket.max < 1 << LOG_SIZE_BUCKET);
        debug_assert_eq!(SIZE_BUCKET, 1 << LOG_SIZE_BUCKET);

        // insert alpha's into Cuckoo table
        let mut table: Vec<Option<u32>> = vec![None; M];
        for mut alpha in alphas.iter().copied() {
            'cuckoo: for iter in 0..CUCKOO_ITERS {
                // try every hash
                for h in HASHES.iter() {
                    let i = h.hash_mod(alpha, M as u32);
                    let e = &mut table[i as usize];
                    if e.is_none() {
                        *e = Some(alpha);
                        break 'cuckoo;
                    }
                }

                // push out
                let i = HASHES[0].hash_mod(alpha, M as u32);
                alpha = mem::replace(&mut table[i as usize], Some(alpha)).unwrap();
                assert!(iter < CUCKOO_ITERS - 1);
            }
        }

        // compute the indexes in each bucket to retrieve
        let p: Vec<usize> = table
            .into_iter()
            .enumerate()
            .map(|(j, e)| match e {
                None => last_bucket,
                Some(alpha) => bucket.pos(j, alpha),
            })
            .collect();

        // run M calls to SPCOT in parallel
        let rh = spcot.extend::<_, _, LOG_SIZE_BUCKET, SIZE_BUCKET>(cache, channel, rng, &p[..])?;
        debug_assert_eq!(rh.len(), M);

        // r[x] := \sum_{i} rh[h_i(x)][pos_(h_i(x))(x)]
        let mut r: Vec<Block> = Vec::with_capacity(N);
        for x in 0..N {
            let mut rx: Block = Default::default();
            for h in HASHES.iter() {
                let hix = h.hash_mod(x as u32, M as u32);
                rx ^= rh[hix as usize][bucket.pos(hix as usize, x as u32)];
            }
            r.push(rx);
        }
        Ok(r)
    }
}
