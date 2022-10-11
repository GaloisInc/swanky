//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::{
    errors::Error,
    ot::{
        kos::{Receiver as KosReceiver, Sender as KosSender},
        CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, RandomReceiver, RandomSender,
        Receiver as OtReceiver, Sender as OtSender,
    },
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};

/// Oblivious transfer extension sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + Malicious> {
    ot: KosSender<OT>,
}
/// Oblivious transfer extension receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + Malicious> {
    ot: KosReceiver<OT>,
}

impl<OT: OtReceiver<Msg = Block> + Malicious> Sender<OT> {
    fn send_setup<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        self.ot.send_setup(channel, m, rng)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> FixedKeyInitializer for Sender<OT> {
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = KosSender::init_fixed_key(channel, s_, rng)?;
        Ok(Self { ot })
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> OtSender for Sender<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = KosSender::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        self.ot.send(channel, inputs, rng)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> CorrelatedSender for Sender<OT> {
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        self.ot.send_correlated(channel, deltas, rng)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> RandomSender for Sender<OT> {
    fn send_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let qs = self.send_setup(channel, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            out.push((q, q ^ self.ot.ot.s_));
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> std::fmt::Display for Sender<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS-Delta Sender")
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> Receiver<OT> {
    fn receive_setup<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        self.ot.receive_setup(channel, inputs, rng)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> OtReceiver for Receiver<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = KosReceiver::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        self.ot.receive(channel, inputs, rng)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        self.ot.receive_correlated(channel, inputs, rng)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> RandomReceiver for Receiver<OT> {
    fn receive_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            out.push(Block::from(t));
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> std::fmt::Display for Receiver<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS-Delta Receiver")
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> SemiHonest for Receiver<OT> {}
impl<OT: OtReceiver<Msg = Block> + Malicious> Malicious for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> Malicious for Receiver<OT> {}
