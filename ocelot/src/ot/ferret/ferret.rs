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
use scuttlebutt::{AbstractChannel, Block};

struct Sender<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer> {
    delta: Block,
    cot: OT, // base COT
}

struct Receiver<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> {
    cot: OT, // base COT
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
        let mut delta: Block = Default::default();
        rng.fill_bytes(delta.as_mut());
        Ok(Self {
            cot: OT::init_fixed_key(channel, delta.into(), rng)?,
            delta,
        })
    }

    fn extend<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let h = 1;
        let q = self.cot.send_random(channel, h, rng)?;
        #[cfg(debug_assertions)]
        {
            for pair in q.iter() {
                debug_assert_eq!(pair.0 ^ pair.1, self.delta, "base COT is not correlated");
            }
        }
        Ok(())
    }
}

mod tests {
    use super::*;

    use std::thread::spawn;

    use rand::rngs::OsRng;
    use scuttlebutt::channel::unix_channel_pair;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender};

    /*
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
    */
}
