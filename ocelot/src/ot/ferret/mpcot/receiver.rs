use std::mem;

use crate::ot::ferret::spcot::Receiver as SPCOTReceiver;

use super::{Buckets, CUCKOO_ITERS, HASHES};

struct Receiver {}

impl Receiver {
    fn extend<const T: usize, const N: usize, const M: usize, const LOG_SIZE_BUCKET: usize>(
        bucket: &Buckets,
        alphas: &[u32; T],
        spcot: &mut SPCOTReceiver,
    ) {
        let last_bucket: usize = (1 << LOG_SIZE_BUCKET) - 1;
        debug_assert!(bucket.max < 1 << LOG_SIZE_BUCKET);

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

        //
        let betas: Vec<usize> = table
            .into_iter()
            .enumerate()
            .map(|(j, e)| match e {
                None => last_bucket,
                Some(alpha) => bucket.pos(j, alpha),
            })
            .collect();
    }
}
