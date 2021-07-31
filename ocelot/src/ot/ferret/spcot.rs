//! Implementation of the SPCOT protocol of Ferret (Figure 6.)
//!
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
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Aes128, AesHash, Block};

struct Sender<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer> {
    delta: Block,
    cot: OT, // base COT
}

struct Receiver<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> {
    cot: OT, // base COT
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

impl<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> Receiver<OT> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            cot: OT::init(channel, rng)?,
        })
    }
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
        })
    }

    fn extend<C: AbstractChannel, RNG: CryptoRng + Rng, const H: usize>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // here we define q as the first message in each pair
        let q = self.cot.send_random(channel, H, rng)?;
        #[cfg(debug_assertions)]
        {
            for pair in q.iter() {
                debug_assert_eq!(pair.0 ^ pair.1, self.delta, "base COT is not correlated");
            }
        }

        // pick root seed
        let s0: Block = rng.gen();

        fn tree_ot<const H: usize>(k: &mut [(Block, Block); H], level: usize, s: Block) {
            if level == H {
                return;
            }
            let (s0, s1) = prg2(s);
            k[level].0 ^= s0;
            k[level].1 ^= s1;
            tree_ot::<H>(k, level + 1, s0);
            tree_ot::<H>(k, level + 1, s1);
        }

        // compute OT messages: at each level the XOR of
        // all the left child seeds and all the right child seeds respectively
        let mut m = [(Default::default(), Default::default()); H];
        tree_ot(&mut m, 0, s0);

        //
        let b: [bool; H] = channel.receive()?;
        let hash = cr_hash();
        for i in 0..H {
            let tweak: Block = (i as u128).into();

            // M^{i}_{0} := K^{i}_{0} ^ H(q_i ^ b_i D, i || l)
            // M^{i}_{1} := K^{i}_{1} ^ H(q_i ^ !b_i D, i || l)
            if b[i] {
                m[i].0 ^= hash.tccr_hash(tweak, q[i].0 ^ self.delta);
                m[i].1 ^= hash.tccr_hash(tweak, q[i].0);
            } else {
                m[i].0 ^= hash.tccr_hash(tweak, q[i].0);
                m[i].1 ^= hash.tccr_hash(tweak, q[i].0 ^ self.delta);
            }
        }
        channel.send(&m)?;

        //

        Ok(())
    }
}

mod tests {
    use super::*;

    use std::thread::spawn;

    use rand::rngs::OsRng;
    use scuttlebutt::channel::unix_channel_pair;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender};

    #[test]
    fn test() {
        let (mut c1, mut c2) = unix_channel_pair();

        let reps: usize = 5;

        let handle = spawn(move || {
            let mut send: Sender<KosDeltaSender> = Sender::init(&mut c2, &mut OsRng).unwrap();
            let out = send.cot.send_random(&mut c2, reps, &mut OsRng);
            println!("{:?}", out);
        });

        let mut recv: Receiver<KosDeltaReceiver> = Receiver::init(&mut c1, &mut OsRng).unwrap();
        //( let out = recv.receive_random(&mut c1, &[true], &mut OsRng).unwrap();

        let select = vec![true; reps];

        let out = recv
            .cot
            .receive_random(&mut c1, &select[..], &mut OsRng)
            .unwrap();
        println!("{:?}", out);

        handle.join().unwrap();
    }
}
