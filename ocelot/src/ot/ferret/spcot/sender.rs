use crate::{
    errors::Error,
    ot::{
        CorrelatedReceiver,
        CorrelatedSender,
        FixedKeyInitializer,
        RandomReceiver,
        RandomSender,
        Receiver as OtReceiver,
        Sender as OtSender,
    },
};
use log;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Aes128, AesHash, Block, F128};
use sha2::{Digest, Sha256};

use std::convert::TryFrom;

use super::*;

pub(crate) struct Sender<
    OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer,
> {
    delta: Block,
    hash: AesHash,
    cot: OT,  // base COT
    l: usize, // repetition of SPCOT
}

impl<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer> Sender<OT> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let delta: Block = rng.gen();
        Ok(Self {
            cot: OT::init_fixed_key(channel, delta.into(), rng)?,
            delta,
            hash: cr_hash(),
            l: 0,
        })
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    fn random_cot<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<Vec<Block>, Error> {
        let cot = self.cot.send_random(channel, len, rng)?;
        #[cfg(debug_assertions)]
        for pair in cot.iter() {
            debug_assert_eq!(pair.0 ^ pair.1, self.delta, "base COT is not correlated");
        }
        Ok(cot.into_iter().map(|v| v.0).collect())
    }

    #[allow(non_snake_case)]
    pub fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // number of parallel repetitions
    ) -> Result<Vec<[Block; N]>, Error> {
        assert_eq!(1 << H, N);

        // acquire base COT
        let cot = self.random_cot(channel, rng, H * num + CSP)?;

        // obtain masked indexes from receiver
        let bs: Vec<usize> = channel.receive_n(num)?;

        //
        let mut vs: Vec<[Block; N]> = Vec::with_capacity(num);
        for (rep, b) in bs.into_iter().enumerate() {
            // used in the computation of "m"
            let q = &cot[H * rep..H * (rep + 1)];

            // pick root seed
            let s0: Block = rng.gen();

            fn gmm_tree_agg(
                k: &mut [(Block, Block)], // left/right sum at every level
                sh: &mut [Block],         // lowest level in the tree
                level: usize,             // level in the tree
                i: usize,                 // position in the tree
                s: Block,                 // root seed
            ) {
                if level == k.len() {
                    sh[i] = s;
                    return;
                }
                let (s0, s1) = prg2(s);
                k[level].0 ^= s0;
                k[level].1 ^= s1;
                let i: usize = i << 1;
                log::trace!("s[{},{}] = {:?}", level + 1, i, s0);
                log::trace!("s[{},{}] = {:?}", level + 1, i | 1, s1);
                gmm_tree_agg(k, sh, level + 1, i, s0);
                gmm_tree_agg(k, sh, level + 1, i | 1, s1);
            }

            // compute OT messages: at each level the XOR of
            // all the left child seeds and all the right child seeds respectively
            let mut m = [(Default::default(), Default::default()); H];
            let mut v: [Block; N] = [Default::default(); N];
            gmm_tree_agg(&mut m, &mut v, 0, 0, s0);

            //
            let b: [bool; H] = unpack_bits::<H>(b);
            let l: u128 = (self.l as u128) << 64;
            log::trace!("b = {:?}", b);

            for i in 0..H {
                let tweak: Block = (l | i as u128).into();

                let h0 = self.hash.tccr_hash(q[i], tweak);
                let h1 = self.hash.tccr_hash(q[i] ^ self.delta, tweak);

                log::trace!("H0 = {:?}", h0);
                log::trace!("H1 = {:?}", h1);

                // M^{i}_{0} := K^{i}_{0} ^ H(q_i ^ b_i D, i || l)
                // M^{i}_{1} := K^{i}_{1} ^ H(q_i ^ !b_i D, i || l)
                if b[i] {
                    m[i].0 ^= h1;
                    m[i].1 ^= h0;
                } else {
                    m[i].0 ^= h0;
                    m[i].1 ^= h1;
                }
            }

            // compute c := Delta + \sum_{i \in[n]} v[i]
            let mut c = self.delta;
            for i in 0..N {
                c ^= v[i];
            }

            // send (m, c) to R
            channel.send(&m)?;
            channel.send(&c)?;
            vs.push(v);

            self.l += 1;
        }

        //
        channel.flush()?;

        // reserve COT for batched consistency check
        log::trace!("consistency check");
        let ys = &cot[num * H..];

        // retrieve coefficients
        let seed: Block = channel.receive()?;
        let xp: Block = channel.receive()?;

        log::trace!("seed = {:?}", seed);
        log::trace!("x' = {:?}", xp);

        let xp: [bool; CSP] = xp.bits();
        let mut y: [Block; CSP] = [Default::default(); CSP];
        for i in 0..num {
            y[i] = ys[i];
            if xp[i] {
                y[i] = y[i] ^ self.delta;
            }
            /*
            Y = Y.mul_x();
            Y = Y + ys[i].into();
            if xp[i] {
                Y = Y + self.delta.into();
            }
            */
        }
        let Y = stack_cyclic(&y);
        log::trace!("Y = {:?}", Y);
        log::trace!("\\Delta = {:?}", self.delta);

        // receive \chi_{i} for i in [n]
        let aes: Aes128 = Aes128::new(seed);
        let mut V: F128 = F128::zero();
        for l in 0..num {
            let xl: F128 = aes.encrypt((l as u128).into()).into();
            let mut xli = xl;
            // X_{i}^{l} = (X^{l})^i
            for i in 0..N {
                log::trace!("X_(l = {})^(i = {}) = {:?}", l, i, xli);

                V = V + xli * vs[l][i].into();

                // X_{i+1}^{l} = X_{i+1}^{l} X_{1}^{l}
                xli = xli * xl;
            }
        }

        // compute Y := \sum_{i \in [k]} z*[i] * X^i
        let V = V + Y;
        log::trace!("V = {:?}", V);

        // Compute and send H(v)
        let Hv = ro_hash(V.into());
        channel.send(&Hv)?;
        Ok(vs)
    }
}
