use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, AesHash, Block, F128};

use std::convert::TryFrom;

use super::*;

pub struct Receiver {
    hash: AesHash,
    l: usize,
}

impl Receiver {
    pub fn init() -> Self {
        Self {
            hash: cr_hash(),
            l: 0,
        }
    }

    #[allow(non_snake_case)]
    pub fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        base_cot: &mut CachedReceiver,
        channel: &mut C,
        rng: &mut RNG,
        alphas: &[usize],
    ) -> Result<Vec<[Block; N]>, Error> {
        assert_eq!(1 << H, N); // H = log2(N)

        // number of SPCOT calls to execute in parallel
        let num = alphas.len();

        // acquire base COT
        let (r, t) = base_cot.get(H * num + CSP).unwrap();

        // send all b's together to avoid multiple flushes
        let mut bs: Vec<usize> = Vec::with_capacity(num);
        for (rep, alpha) in alphas.iter().copied().enumerate() {
            // mask index: generate b
            debug_assert!(alpha < N);
            let r: usize = pack_bits(&r[H * rep..H * (rep + 1)]);
            let b: usize = r ^ alpha ^ ((1 << H) - 1);
            bs.push(b);
        }
        channel.send(&bs[..])?;
        channel.flush()?;

        // allocate result vector
        let mut ws: Vec<[Block; N]> = Vec::with_capacity(num);
        unsafe { ws.set_len(num) };

        for (rep, alpha) in alphas.iter().copied().enumerate() {
            let a: [bool; H] = unpack_bits::<H>(alpha);
            let t: &[Block] = &t[H * rep..H * (rep + 1)];

            // receive (m, c) from S
            let m: [(Block, Block); H] = channel.receive()?;
            let c: Block = channel.receive()?;
            let l: u128 = (self.l as u128) << 64;

            // compute the leafs in the GGM tree
            let si: &mut [Block; N] = &mut ws[rep];
            for i in 0..H {
                // compute a_s = a_i* = a_1,...,a_{i-1},~a_{i}
                let s: usize = H - i - 1;
                let a_s: usize = (alpha >> s) ^ 0x1;

                // compute a_s = a_i* = a_1,...,a_{i-1}
                let a_sm: usize = a_s >> 1;

                // compute ~a_i
                let nai: usize = a_s & 1;

                // M_{~a[i]}^i
                let mna = if a[i] { m[i].0 } else { m[i].1 };

                // K_{~a[i]}^i := M_{~a[i]}^i ^ H(t_i, i || l)
                let tweak: Block = (l | i as u128).into();
                let h = self.hash.tccr_hash(t[i], tweak);
                let kna = mna ^ h;

                // expand the seeds (in-place)
                if i == 0 {
                    // If i == 1, define s_{~a[1]} := K_{~a[1]}^1
                    si[nai] = kna;
                } else {
                    // If i >= 2: j \in [2^(i - 1)], j \neq a_1, ..., a_{i-1}:
                    //    compute (s^{i}_{2j}, s^{i}_{2j + 1}) := G(s_j^{i-1})
                    let mut j = (1 << i) - 1;
                    loop {
                        debug_assert!(si[j] != Block::default() || j == a_sm);
                        let (s0, s1) = prg2(&self.hash, si[j]);
                        si[2 * j] = s0;
                        si[2 * j + 1] = s1;
                        if j == 0 {
                            break;
                        }
                        j -= 1;
                    }
                }

                // compute s_{a_i^*}^i :=
                si[a_s] = kna;
                for j in 0..(1 << i) {
                    if j != a_sm {
                        si[a_s] ^= si[2 * j + nai];
                    }
                }
            }

            si[alpha] = c;
            for i in 0..N {
                if i != alpha {
                    si[alpha] ^= si[i];
                }
            }

            self.l += 1;
        }

        // parallel consistency check
        let xs = &r[H * num..];
        let zs = &t[H * num..];
        debug_assert_eq!(xs.len(), CSP);
        debug_assert_eq!(zs.len(), CSP);

        // send a seed from which all the changes are derived
        let seed: Block = rng.gen();
        let mut gen = BiasedGen::new(seed);

        // derive random coefficients
        let mut W = (Block::default(), Block::default()); // defer GF(2^128) reduction
        let mut phi: F128 = F128::zero();
        for (l, alpha) in alphas.iter().copied().enumerate() {
            // X_{i}^{l} = (X^{l})^i
            for i in 0..N {
                let xli: F128 = gen.next();
                let cm = xli.cmul(ws[l][i].into());
                W.0 ^= cm.0;
                W.1 ^= cm.1;
                if i == alpha {
                    phi = phi + xli;
                }
            }
        }
        let W: F128 = F128::reduce(W);

        // pack the choice bits into a 128-bit block
        let xs = <&[bool; 128]>::try_from(xs).unwrap();
        let xs: Block = Block::from(xs);

        // mask the alpha sum
        let phi: Block = phi.into();
        let xp: Block = phi ^ xs;

        // send coefficients and masked sum to the sender
        channel.send(&xp)?;
        channel.send(&seed)?;
        channel.flush()?;

        // compute Z := \sum_{i \in [k]} z*[i] * X^i
        let Z = stack_cyclic(<&[Block; CSP]>::try_from(zs).unwrap());
        let W = W + Z;

        // calculate hash H(w) locally
        let Hw: [u8; 32] = ro_hash(W.into());

        // obtain hash from sender
        let Hv: [u8; 32] = channel.receive()?;
        if Hv != Hw {
            return Err(Error::Other("consistency check failed".to_owned()));
        } else {
            Ok(ws)
        }
    }
}
