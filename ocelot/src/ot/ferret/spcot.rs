//! Implementation of the SPCOT protocol of Ferret (Figure 6.)
//!
//! The notation is kept as close as possible to that of the paper.
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

use super::CSP;

struct Sender<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer> {
    delta: Block,
    cot: OT,  // base COT
    l: usize, // repetition of SPCOT
}

struct Receiver<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> {
    cot: OT,  // base COT
    l: usize, // repetition of SPCOT
}

fn cr_hash() -> AesHash {
    AesHash::new(Default::default())
}

fn prg2(k: Block) -> (Block, Block) {
    let aes = Aes128::new(k);
    (
        aes.encrypt(Block::from(0u128)),
        aes.encrypt(Block::from(1u128)),
    )
}

// MSB
fn unpack_bits<const N: usize>(mut n: usize) -> [bool; N] {
    debug_assert!(n < (1 << N));
    let mut b: [bool; N] = [false; N];
    let mut j: usize = N - 1;
    loop {
        b[j] = (n & 1) != 0;
        n >>= 1;
        if j == 0 {
            break b;
        }
        j -= 1;
    }
}

fn pack_bits(bits: &[bool]) -> usize {
    debug_assert!(bits.len() <= 64);
    let mut n = 0;
    for b in bits.iter().copied() {
        n <<= 1;
        n |= b as usize;
    }
    n
}

impl<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer> Sender<OT> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let delta: Block = rng.gen();
        Ok(Self {
            cot: OT::init_fixed_key(channel, delta.into(), rng)?,
            delta,
            l: 0,
        })
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

    fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<[Block; N], Error> {
        assert_eq!(1 << H, N);

        let cot = self.random_cot(channel, rng, H + CSP)?;

        // used in the computation of "m"
        let q = &cot[..H];

        // y* used in consistency check
        let ys = &cot[H..];

        // pick root seed
        let s0: Block = rng.gen();

        fn tree_ot<const H: usize, const N: usize>(
            k: &mut [(Block, Block); H], // left/right sum at every level
            sh: &mut [Block; N],         // lowest level in the tree
            level: usize,                // level in the tree
            i: usize,                    // position in the tree
            s: Block,                    // root seed
        ) {
            if level == H {
                sh[i] = s;
                return;
            }
            let (s0, s1) = prg2(s);
            k[level].0 ^= s0;
            k[level].1 ^= s1;
            let i: usize = i << 1;
            log::trace!("s: s[{},{}] = {:?}", level + 1, i, s0);
            log::trace!("s: s[{},{}] = {:?}", level + 1, i | 1, s1);
            tree_ot(k, sh, level + 1, i, s0);
            tree_ot(k, sh, level + 1, i | 1, s1);
        }

        // compute OT messages: at each level the XOR of
        // all the left child seeds and all the right child seeds respectively
        let mut m = [(Default::default(), Default::default()); H];
        let mut v: [Block; N] = [Default::default(); N];
        tree_ot(&mut m, &mut v, 0, 0, s0);

        //
        let hash = cr_hash();
        let b: usize = channel.receive()?;
        let b: [bool; H] = unpack_bits::<H>(b);
        let l: u128 = (self.l as u128) << 64;

        log::trace!("s: b = {:?}", b);

        for i in 0..H {
            let tweak: Block = (l | i as u128).into();

            let h0 = hash.tccr_hash(q[i], tweak);
            let h1 = hash.tccr_hash(q[i] ^ self.delta, tweak);

            log::trace!("s: H0 = {:?}", h0);
            log::trace!("s: H1 = {:?}", h1);

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
        channel.flush()?;

        /*

        // receive \chi_{i} for i in [n]
        let chi: [Block; N] = channel.receive()?;

        // receive x' := x + x* \in F_{2}^{\kappa}
        // Note that this element is to be understood as a element of the vector space
        // (F_2)^\kappa, not the extension field.
        let xp: Block = channel.receive()?;
        let xp: [bool; CSP] = xp.bits();

        // Embedding each element of xp[i] from F_2 into F_{2^\kappa}
        let mut Y: F128 = F128::zero();
        let Xi = F128::one();
        for i in 0..CSP {
            Y = Y.mul_x();
            if xp[i] {
                Y = Y + ys[i].0.into() + self.delta.into();
            } else {
                Y = Y + ys[i].0.into()
            }
        }

        let mut V: (Block, Block) = (Default::default(), Y.into());
        for i in 0..CSP {
            let (h, l) = Block::clmul(chi[i], v[i]);
            V.0 ^= h;
            V.1 ^= l;
        }

        let mut hsh = Sha256::new();
        hsh.update(V.0.as_ref());
        hsh.update(V.1.as_ref());

        let hsh: [u8; 32] = hsh.finalize().into();
        channel.send(&hsh)?;
        channel.flush()?;
        */
        Ok(v)
    }
}

impl<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> Receiver<OT> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            cot: OT::init(channel, rng)?,
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

    fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize, const N: usize>(
        &mut self,
        alpha: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<[Block; N], Error> {
        debug_assert!(alpha < N);
        assert_eq!(1 << H, N);

        // random ot
        let (r, t) = self.random_cot(channel, rng, CSP + H)?;

        // mask index: generate b
        let r: usize = pack_bits(&r[..H]);
        let b: usize = r ^ alpha ^ ((1 << H) - 1);
        let a: [bool; H] = unpack_bits::<H>(alpha);
        log::trace!("r: b = {:?}", unpack_bits::<H>(b));

        // send b to R
        channel.send(b)?;
        channel.flush()?;

        // receive (m, c) from S
        let m: [(Block, Block); H] = channel.receive()?;
        let c: Block = channel.receive()?;
        let hash = cr_hash();
        let l: u128 = (self.l as u128) << 64;

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
            let h = hash.tccr_hash(t[i], tweak);
            log::trace!(
                "r: H(~b[{}]) = H{} = {:?}",
                i,
                (!unpack_bits::<H>(b)[i]) as usize,
                h
            );
            let kna = mna ^ h;
            log::trace!("r: K_(na)^{} = {:?}", i, kna);

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

        Ok(si)
    }
}

mod tests {
    use super::*;

    use std::thread::spawn;

    use rand::rngs::OsRng;
    use scuttlebutt::channel::unix_channel_pair;

    use simple_logger;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender};

    #[test]
    fn test() {
        let _ = simple_logger::init();
        let (mut c1, mut c2) = unix_channel_pair();

        let handle = spawn(move || {
            let mut send: Sender<KosDeltaSender> = Sender::init(&mut c2, &mut OsRng).unwrap();
            let v = send.extend::<_, _, 2, 4>(&mut c2, &mut OsRng).unwrap();
            println!("{:?}", v);
            (send.delta, v)
        });

        let mut recv: Receiver<KosDeltaReceiver> = Receiver::init(&mut c1, &mut OsRng).unwrap();
        //( let out = recv.receive_random(&mut c1, &[true], &mut OsRng).unwrap();

        let alpha = 3;

        let w = recv
            .extend::<_, _, 2, 4>(alpha, &mut c1, &mut OsRng)
            .unwrap();
        println!("{:?}", w);

        let (delta, mut v) = handle.join().unwrap();

        v[alpha] ^= delta;
        assert_eq!(v, w, "correlation not satisfied");
    }
}
