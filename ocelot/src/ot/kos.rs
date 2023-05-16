//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::{
    errors::Error,
    ot::FixedKeyInitializer,
    ot::{
        alsz::{Receiver as AlszReceiver, Sender as AlszSender},
        CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver as OtReceiver,
        Sender as OtSender,
    },
    utils,
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{cointoss, AbstractChannel, AesRng, Block, Malicious, SemiHonest};
use std::io::ErrorKind;

// The statistical security parameter.
const SSP: usize = 40;

/// Oblivious transfer extension sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + Malicious> {
    pub(super) ot: AlszSender<OT>,
}

/// Oblivious transfer extension receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + Malicious> {
    ot: AlszReceiver<OT>,
}

impl<OT: OtReceiver<Msg = Block> + Malicious> Sender<OT> {
    pub(super) fn send_setup<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        let m = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let ncols = m + 128 + SSP;
        let qs = self.ot.send_setup(channel, ncols)?;
        // Check correlation
        let mut seed = Block::default();
        rng.fill_bytes(seed.as_mut());
        let seed = cointoss::send(channel, &[seed])?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut check = (Block::default(), Block::default());
        let mut chi = Block::default();
        for j in 0..ncols {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            rng.fill_bytes(chi.as_mut());
            let tmp = q.clmul(chi);
            check = utils::xor_two_blocks(&check, &tmp);
        }
        let x = channel.read_block()?;
        let t0 = channel.read_block()?;
        let t1 = channel.read_block()?;
        let tmp = x.clmul(self.ot.s_);
        let check = utils::xor_two_blocks(&check, &tmp);
        if check != (t0, t1) {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidData,
                "Consistency check failed",
            )));
        }
        Ok(qs)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> FixedKeyInitializer for Sender<OT> {
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = AlszSender::<OT>::init_fixed_key(channel, s_, rng)?;
        Ok(Self { ot })
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> OtSender for Sender<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = AlszSender::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m, rng)?;
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.ot.s_;
            let y1 = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ input.1;
            channel.write_block(&y0)?;
            channel.write_block(&y1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> CorrelatedSender for Sender<OT> {
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(channel, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = self.ot.hash.tccr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.ot.s_;
            let y = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ x1;
            channel.write_block(&y)?;
            out.push((x0, x1));
        }
        channel.flush()?;
        Ok(out)
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
            let x0 = self.ot.hash.tccr_hash(Block::from(j as u128), q);
            let q = q ^ self.ot.s_;
            let x1 = self.ot.hash.tccr_hash(Block::from(j as u128), q);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> std::fmt::Display for Sender<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS Sender")
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> Receiver<OT> {
    pub(super) fn receive_setup<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        let m = inputs.len();
        let m = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let m_ = m + 128 + SSP;
        let mut r = utils::boolvec_to_u8vec(inputs);
        r.extend((0..(m_ - m) / 8).map(|_| rand::random::<u8>()));
        let ts = self.ot.receive_setup(channel, &r, m_)?;
        // Check correlation
        let mut seed = Block::default();
        rng.fill_bytes(seed.as_mut());
        let seed = cointoss::receive(channel, &[seed])?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut x = Block::default();
        let mut t = (Block::default(), Block::default());
        let r_ = utils::u8vec_to_boolvec(&r);
        let mut chi = Block::default();
        for (j, xj) in r_.into_iter().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj: [u8; 16] = tj.try_into().unwrap();
            let tj = Block::from(tj);
            rng.fill_bytes(chi.as_mut());
            x ^= if xj { chi } else { Block::default() };
            let tmp = tj.clmul(chi);
            t = utils::xor_two_blocks(&t, &tmp);
        }
        channel.write_block(&x)?;
        channel.write_block(&t.0)?;
        channel.write_block(&t.1)?;
        channel.flush()?;
        Ok(ts)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> OtReceiver for Receiver<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = AlszReceiver::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        // Output result
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y0 = channel.read_block()?;
            let y1 = channel.read_block()?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self
                .ot
                .hash
                .tccr_hash(Block::from(j as u128), Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = channel.read_block()?;
            let y = if *b { y } else { Block::default() };
            let h = self
                .ot
                .hash
                .tccr_hash(Block::from(j as u128), Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
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
            let h = self
                .ot
                .hash
                .tccr_hash(Block::from(j as u128), Block::from(t));
            out.push(h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> std::fmt::Display for Receiver<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS Receiver")
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> SemiHonest for Receiver<OT> {}
impl<OT: OtReceiver<Msg = Block> + Malicious> Malicious for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> Malicious for Receiver<OT> {}
