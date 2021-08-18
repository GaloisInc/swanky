use super::*;

use crate::errors::Error;

use scuttlebutt::AbstractChannel;

use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

pub struct Sender {}

impl Sender {
    pub fn extend_setup<C: AbstractChannel, R: Rng + CryptoRng>(
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        Self::extend::<
            _,
            _,
            SETUP_K,
            SETUP_N,
            SETUP_T,
            SETUP_M,
            CODE_D,
            SETUP_BUCKET_LOG_SIZE,
            SETUP_BUCKET_SIZE,
        >(&SETUP_CODE, &SETUP_BUCKETS, base, spcot, rng, channel)
    }

    pub fn extend_main<C: AbstractChannel, R: Rng + CryptoRng>(
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        Self::extend::<
            _,
            _,
            MAIN_K,
            MAIN_N,
            MAIN_T,
            MAIN_M,
            CODE_D,
            MAIN_BUCKET_LOG_SIZE,
            MAIN_BUCKET_SIZE,
        >(&MAIN_CODE, &MAIN_BUCKETS, base, spcot, rng, channel)
    }

    pub fn extend<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const K: usize,
        const N: usize,
        const T: usize,
        const M: usize,
        const D: usize,
        const LOG_SIZE_BUCKET: usize,
        const SIZE_BUCKET: usize,
    >(
        code: &LLCode<K, N, D>,
        buckets: &Buckets,
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        let s: Vec<Block> = mpcot::Sender::extend::<C, R, T, N, M, LOG_SIZE_BUCKET, SIZE_BUCKET>(
            buckets, base, spcot, channel, rng,
        )?;

        // obtain K base COTs
        let v = base.get(K).unwrap();

        // compute y := v * A + s
        let mut y = code.mul(<&[Block; K]>::try_from(&v[..]).unwrap());
        for (dst, src) in y.iter_mut().zip(s.into_iter()) {
            *dst ^= src;
        }
        Ok(y)
    }
}
