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

use std::convert::TryFrom;

use super::*;

pub(crate) struct Receiver<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> {
    cot: OT, // base COT
    hash: AesHash,
    l: usize, // repetition of SPCOT
}

impl<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> Receiver<OT> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            cot: OT::init(channel, rng)?,
            hash: cr_hash(),
            l: 0,
        })
    }

    fn random_cot<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<(Vec<bool>, Vec<Block>), Error> {
        let r: Vec<bool> = (0..len).map(|_| rng.gen()).collect();
        let t = self.cot.receive_random(channel, &r[..], rng)?;
        Ok((r, t))
    }

    #[allow(non_snake_case)]
    pub fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        alphas: &[usize],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<[Block; N]>, Error> {
        assert_eq!(1 << H, N); // H = log2(N)

        // number of SPCOT calls to execute in parallel
        let num = alphas.len();

        // acquire base COT
        let (r, t) = self.random_cot(channel, rng, H * num + CSP)?;

        // send all b's together to avoid multiple flushes
        let mut bs: Vec<usize> = Vec::with_capacity(num);
        for (rep, alpha) in alphas.iter().copied().enumerate() {
            // mask index: generate b
            debug_assert!(alpha < N);
            let r: usize = pack_bits(&r[H * rep..H * (rep + 1)]);
            let b: usize = r ^ alpha ^ ((1 << H) - 1);
            log::trace!("b = {:?}", unpack_bits::<H>(b));
            bs.push(b);
        }
        channel.send(&bs[..])?;
        channel.flush()?;

        // GGM tree
        let mut ws: Vec<[Block; N]> = Vec::with_capacity(num);
        for (rep, (alpha, b)) in alphas.iter().copied().zip(bs.into_iter()).enumerate() {
            let a: [bool; H] = unpack_bits::<H>(alpha);
            let t: &[Block] = &t[H * rep..H * (rep + 1)];

            // receive (m, c) from S
            let m: [(Block, Block); H] = channel.receive()?;
            let c: Block = channel.receive()?;
            let l: u128 = (self.l as u128) << 64;

            // compute the leafs in the GGM tree
            let mut si: [Block; N] = [Default::default(); N];
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
                log::trace!(
                    "H(~b[{}]) = H{} = {:?}",
                    i,
                    (!unpack_bits::<H>(b)[i]) as usize,
                    h
                );
                let kna = mna ^ h;
                log::trace!("K_(na)^{} = {:?}", i, kna);

                // expand the seeds (in-place)
                if i == 0 {
                    // If i == 1, define s_{~a[1]} := K_{~a[1]}^1
                    si[nai] = kna;
                } else {
                    // If i >= 2: j \in [2^(i - 1)], j \neq a_1, ..., a_{i-1}:
                    //    compute (s^{i}_{2j}, s^{i}_{2j + 1}) := G(s_j^{i-1})
                    let mut j = 1 << (i - 1);
                    loop {
                        debug_assert!(si[j] != Block::default() || j == a_sm);
                        log::trace!("r: s = {:?}", si[j]);
                        let (s0, s1) = prg2(si[j]);
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
            ws.push(si);

            self.l += 1;
        }

        log::trace!("consistency check");

        // parallel consistency check
        let xs = &r[H * num..];
        let zs = &t[H * num..];
        debug_assert_eq!(xs.len(), CSP);
        debug_assert_eq!(zs.len(), CSP);

        // send a seed from which all the changes are derived
        let seed: Block = rng.gen();
        log::trace!("seed = {:?}", seed);

        // derive random coefficients
        let aes: Aes128 = Aes128::new(seed);
        let mut W: F128 = F128::zero();
        let mut phi: F128 = F128::zero();
        for (l, alpha) in alphas.iter().copied().enumerate() {
            let xl: F128 = aes.encrypt((l as u128).into()).into();
            let mut xli = xl;

            // X_{i}^{l} = (X^{l})^i
            for i in 0..N {
                log::trace!("X_(l = {})^(i = {}) = {:?}", l, i, xli);

                W = W + xli * ws[l][i].into();

                if i == alpha {
                    phi = phi + xli;
                }

                // X_{i+1}^{l} = X_{i+1}^{l} X_{1}^{l}
                xli = xli * xl;
            }
        }

        // pack the choice bits into a 128-bit block
        let xs = <&[bool; 128]>::try_from(xs).unwrap();
        let xs: Block = Block::from(xs);
        log::trace!("x* = {:?}", xs);

        // mask the alpha sum
        let phi: Block = phi.into();
        let xp: Block = phi ^ xs;
        log::trace!("x' = {:?}", xp);

        // send coefficients and masked sum to the sender
        channel.send(&seed)?;
        channel.send(&xp)?;
        channel.flush()?;

        // compute Z := \sum_{i \in [k]} z*[i] * X^i
        let Z = stack_cyclic(<&[Block; CSP]>::try_from(zs).unwrap());
        let W = W + Z;
        log::trace!("Z = {:?}", Z);
        log::trace!("\\phi = {:?}", phi);
        log::trace!("W = {:?}", W);

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
