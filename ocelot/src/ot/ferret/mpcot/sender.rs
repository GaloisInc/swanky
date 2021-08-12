use crate::{
    errors::Error,
    ot::ferret::{cache::CachedSender, spcot::Sender as SPCOTSender},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

use std::mem;

use super::{Buckets, CUCKOO_ITERS, HASHES};

pub(crate) struct Sender {}

impl Sender {
    pub(crate) fn extend<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const T: usize,
        const N: usize,
        const M: usize,
        const LOG_SIZE_BUCKET: usize,
        const SIZE_BUCKET: usize,
    >(
        bucket: &Buckets,         // precomputed bucket lookup
        cache: &mut CachedSender, // bag of base-COT
        spcot: &mut SPCOTSender,  // SPCOT implementation
        channel: &mut C,          // communication channel
        rng: &mut R,              // cryptographically secure RNG
    ) -> Result<Vec<Block>, Error> {
        let sh = spcot.extend::<_, _, LOG_SIZE_BUCKET, SIZE_BUCKET>(cache, channel, rng, M)?;
        let mut s: Vec<Block> = Vec::with_capacity(N);
        for x in 0..N {
            let mut rx: Block = Default::default();
            for h in HASHES.iter() {
                let hix = h.hash_mod(x as u32, M as u32);
                rx ^= sh[hix as usize][bucket.pos(hix as usize, x as u32)];
            }
            s.push(rx);
        }
        debug_assert_eq!(s.len(), N);
        Ok(s)
    }
}
