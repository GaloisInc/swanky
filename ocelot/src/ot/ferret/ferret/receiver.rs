use super::*;

use crate::errors::Error;

use scuttlebutt::{AbstractChannel, Block};

use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

pub struct Receiver<const REG: bool> {}

#[inline(always)]
fn finalize<const K: usize, const N: usize, const D: usize, const T: usize>(
    code: &LLCode<K, N, D>,
    base: &mut CachedReceiver,
    r: Vec<Block>,
    e: &[usize; T], // error positions
) -> (Vec<bool>, Vec<Block>) {
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
    (x, z)
}

impl<const REG: bool> Receiver<REG> {
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
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
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
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
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
        base: &mut CachedReceiver,   // base COTs
        spcot: &mut spcot::Receiver, // SPCOT functionality
        rng: &mut R,
        channel: &mut C,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
        // error positions
        let e = util::random_array::<_, T>(rng, SPLEN);

        //
        let mut r = mpcot::Receiver::extend_reg::<C, R, T, N, LOG_SPLEN, SPLEN>(
            base, spcot, channel, rng, &e,
        )?;

        //
        let (u, w) = base.get(K).unwrap();

        // compute x := u * A + e \in F_{2}^n
        let mut x = code.mul(<&[bool; K]>::try_from(&u[..]).unwrap());
        for (c, i) in x.chunks_exact_mut(SPLEN).zip(e.iter().copied()) {
            c[i] ^= true;
        }

        // compute z := w * A + r \in F_{2^k}^n
        code.mul_add(
            <&[Block; K]>::try_from(&w[..]).unwrap(),
            <&mut [Block; N]>::try_from(&mut r[..]).unwrap(), // z = r (updated in-place)
        );

        Ok((x, r))
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

        Ok(finalize(code, base, r, &e))
    }
}
