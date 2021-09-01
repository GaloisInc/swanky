use super::*;

use crate::errors::Error;

use scuttlebutt::AbstractChannel;

use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

pub struct Sender<const REG: bool> {}

fn finalize<const K: usize, const N: usize, const D: usize>(
    code: &LLCode<K, N, D>,
    base: &mut CachedSender,
    mut s: Vec<Block>,
) -> Vec<Block> {
    // obtain K base COTs
    let v = base.get(K).unwrap();

    // compute y := v * A + s
    code.mul_add(
        <&[Block; K]>::try_from(&v[..]).unwrap(),
        <&mut [Block; N]>::try_from(&mut s[..]).unwrap(),
    );
    s
}

impl<const REG: bool> Sender<REG> {
    #[inline]
    pub const fn cots_setup() -> usize {
        if REG {
            REG_SETUP_COTS
        } else {
            UNI_SETUP_COTS
        }
    }

    #[inline]
    pub const fn cots_main() -> usize {
        if REG {
            REG_MAIN_COTS
        } else {
            UNI_MAIN_COTS
        }
    }

    pub fn extend_setup<C: AbstractChannel, R: Rng + CryptoRng>(
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        if REG {
            Self::extend_reg::<
                _,
                _,
                REG_SETUP_K,
                REG_SETUP_N,
                REG_SETUP_T,
                CODE_D,
                REG_SETUP_LOG_SPLEN,
                REG_SETUP_SPLEN,
            >(&REG_SETUP_CODE, base, spcot, rng, channel)
        } else {
            Self::extend::<
                _,
                _,
                UNI_SETUP_K,
                UNI_SETUP_N,
                UNI_SETUP_T,
                UNI_SETUP_M,
                CODE_D,
                UNI_SETUP_BUCKET_LOG_SIZE,
                UNI_SETUP_BUCKET_SIZE,
            >(
                &UNI_SETUP_CODE,
                &UNI_SETUP_BUCKETS,
                base,
                spcot,
                rng,
                channel,
            )
        }
    }

    pub fn extend_main<C: AbstractChannel, R: Rng + CryptoRng>(
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        if REG {
            Self::extend_reg::<
                _,
                _,
                REG_MAIN_K,
                REG_MAIN_N,
                REG_MAIN_T,
                CODE_D,
                REG_MAIN_LOG_SPLEN,
                REG_MAIN_SPLEN,
            >(&REG_MAIN_CODE, base, spcot, rng, channel)
        } else {
            Self::extend::<
                _,
                _,
                UNI_MAIN_K,
                UNI_MAIN_N,
                UNI_MAIN_T,
                UNI_MAIN_M,
                CODE_D,
                UNI_MAIN_BUCKET_LOG_SIZE,
                UNI_MAIN_BUCKET_SIZE,
            >(&UNI_MAIN_CODE, &UNI_MAIN_BUCKETS, base, spcot, rng, channel)
        }
    }

    pub fn extend_reg<
        C: AbstractChannel,
        R: Rng + CryptoRng,
        const K: usize,
        const N: usize,
        const T: usize,
        const D: usize,
        const LOG_SPLEN: usize,
        const SPLEN: usize,
    >(
        code: &LLCode<K, N, D>,
        base: &mut CachedSender,   // base COTs
        spcot: &mut spcot::Sender, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<Vec<Block>, Error> {
        let s: Vec<Block> =
            mpcot::Sender::extend_reg::<C, R, T, N, LOG_SPLEN, SPLEN>(base, spcot, channel, rng)?;
        Ok(finalize(code, base, s))
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
        Ok(finalize(code, base, s))
    }
}
