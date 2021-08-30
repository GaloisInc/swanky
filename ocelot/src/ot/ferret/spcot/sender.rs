use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, AesHash, Block, F128};

use super::*;

pub struct Sender {
    hash: AesHash,
    pub(crate) delta: Block,
    l: usize, // repetition of SPCOT
}

impl Sender {
    pub fn init(delta: Block) -> Self {
        Self {
            delta,
            hash: cr_hash(),
            l: 0,
        }
    }

    #[allow(non_snake_case)]
    pub fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        base_cot: &mut CachedSender,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // number of parallel repetitions
    ) -> Result<Vec<[Block; N]>, Error> {
        assert_eq!(1 << H, N);
        debug_assert_eq!(base_cot.delta(), self.delta);

        // acquire base COT
        let cot = base_cot.get(H * num + CSP).unwrap();

        // create result vector
        let mut vs: Vec<[Block; N]> = Vec::with_capacity(num);
        unsafe { vs.set_len(num) };

        // obtain masked indexes from receiver
        let bs: Vec<usize> = channel.receive_n(num)?;

        //
        for (rep, b) in bs.into_iter().enumerate() {
            // used in the computation of "m"
            let q = &cot[H * rep..H * (rep + 1)];

            // compute OT messages: at each level the XOR of
            // all the left child seeds and all the right child seeds respectively
            let mut m: [(Block, Block); H] = [(Default::default(), Default::default()); H];
            let v: &mut [Block; N] = &mut vs[rep];

            // pick root seed
            v[0] = rng.gen();

            for i in 0..H {
                let mut j = (1 << i) - 1;
                loop {
                    let res = prg2(&self.hash, v[j]);
                    m[i].0 ^= res.0;
                    m[i].1 ^= res.1;
                    v[2 * j] = res.0;
                    v[2 * j + 1] = res.1;
                    if j == 0 {
                        break;
                    }
                    j -= 1;
                }
            }

            let b: [bool; H] = unpack_bits::<H>(b);
            let l: u128 = (self.l as u128) << 64;

            for i in 0..H {
                let tweak: Block = (l | i as u128).into();

                let h0 = self.hash.tccr_hash(q[i], tweak);
                let h1 = self.hash.tccr_hash(q[i] ^ self.delta, tweak);

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

            self.l += 1;
        }

        //
        channel.flush()?;

        // reserve COT for batched consistency check
        let ys = &cot[num * H..];

        // retrieve coefficients
        let xp: Block = channel.receive()?;
        let xp: [bool; CSP] = xp.into();
        let mut y: [Block; CSP] = [Default::default(); CSP];
        for i in 0..CSP {
            y[i] = ys[i];
            if xp[i] {
                y[i] = y[i] ^ self.delta;
            }
        }
        let Y = stack_cyclic(&y);

        // receive \chi_{i} for i in [n]
        let seed: Block = channel.receive()?;
        let mut gen = BiasedGen::new(seed);
        let mut V = (Block::default(), Block::default());
        for l in 0..num {
            // X_{i}^{l} = (X^{l})^i
            for i in 0..N {
                let xli: F128 = gen.next();
                let cm = xli.cmul(vs[l][i].into());
                V.0 ^= cm.0;
                V.1 ^= cm.1;
            }
        }
        let V = F128::reduce(V);

        // compute Y := \sum_{i \in [k]} z*[i] * X^i
        let V = V + Y;

        // Compute and send H(v)
        let Hv = ro_hash(V.into());
        channel.send(&Hv)?;
        Ok(vs)
    }
}
