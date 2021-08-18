use super::*;

use crate::errors::Error;

use scuttlebutt::AbstractChannel;

use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

pub struct Receiver {}

impl Receiver {
    pub fn extend_setup<C: AbstractChannel, R: Rng + CryptoRng>(
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
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
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
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
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
        // error positions
        let e = util::unique_random_array::<_, T>(rng, N);

        //
        let r = mpcot::Receiver::extend::<C, R, T, N, M, LOG_SIZE_BUCKET, SIZE_BUCKET>(
            buckets, base, spcot, channel, rng, &e,
        )?;

        //
        let (u, w) = base.get(K).unwrap();

        // compute x := u * A + e \in F_{2}^n
        let mut x = code.mul(<&[bool; K]>::try_from(&u[..]).unwrap());
        for i in e.iter().copied() {
            x[i] ^= true;
        }

        // compute z := w * A + r \in F_{2^k}^n
        let mut z = code.mul(<&[Block; K]>::try_from(&w[..]).unwrap());
        for (dst, src) in z.iter_mut().zip(r.into_iter()) {
            *dst ^= src;
        }
        Ok((x, z))
    }
}
