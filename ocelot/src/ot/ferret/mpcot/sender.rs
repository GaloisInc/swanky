use crate::{
    errors::Error,
    ot::ferret::{cache::CachedSender, spcot::Sender as SPCOTSender},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

use super::{combine_buckets, Buckets};

pub struct Sender {}

impl Sender {
    pub fn extend<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const T: usize,
        const N: usize,
        const M: usize,
        const LOG_SIZE_BUCKET: usize,
        const SIZE_BUCKET: usize,
    >(
        buckets: &Buckets,        // precomputed bucket lookup
        cache: &mut CachedSender, // bag of base-COT
        spcot: &mut SPCOTSender,  // SPCOT implementation
        channel: &mut C,          // communication channel
        rng: &mut R,              // cryptographically secure RNG
    ) -> Result<Vec<Block>, Error> {
        let sh: Vec<[Block; SIZE_BUCKET]> =
            spcot.extend::<_, _, LOG_SIZE_BUCKET, SIZE_BUCKET>(cache, channel, rng, M)?;
        let mut s: Vec<Block> = Vec::with_capacity(N);
        for x in 0..N {
            s.push(combine_buckets(x, M, buckets, &sh[..]));
        }
        debug_assert_eq!(s.len(), N);
        Ok(s)
    }
}
