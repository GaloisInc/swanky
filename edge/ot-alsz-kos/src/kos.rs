//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::alsz::{Receiver as AlszReceiver, Sender as AlszSender};
use rand::{CryptoRng, Rng, SeedableRng};
use swanky_adversary::{Malicious, SemiHonest};
use swanky_channel_legacy::AbstractChannel;
use swanky_cointoss;
use swanky_cr_hash::TweakableCircularCorrelationRobustHash;
use swanky_error::{ErrorKind, Result, WrapErr, ensure};
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer};
use swanky_ot_traits::{
    CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, RandomReceiver, RandomSender,
    Receiver as OtReceiver, Sender as OtSender,
};
use swanky_rng::SwankyRng;
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

// The statistical security parameter.
const SSP: usize = 40;

/// Oblivious transfer extension sender.
pub struct Sender<OT: OtReceiver<Msg = U8x16> + Malicious = swanky_ot_chou_orlandi::Receiver> {
    pub(super) ot: AlszSender<OT>,
}

/// Oblivious transfer extension receiver.
pub struct Receiver<OT: OtSender<Msg = U8x16> + Malicious = swanky_ot_chou_orlandi::Sender> {
    ot: AlszReceiver<OT>,
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> Sender<OT> {
    pub(super) fn send_setup<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<u8>> {
        let m = if !m.is_multiple_of(8) {
            m + (8 - m % 8)
        } else {
            m
        };
        let ncols = m + 128 + SSP;
        let qs = self.ot.send_setup(channel, ncols)?;
        // Check correlation
        let mut seed = U8x16::default();
        rng.fill_bytes(seed.as_mut());
        let seed = swanky_cointoss::send(channel, &[seed])
            .wrap_err(ErrorKind::NetworkError, "Unable to send cointoss")?;
        let mut rng = SwankyRng::from_seed(seed[0]);
        let mut check = (U8x16::default(), U8x16::default());
        let mut chi = U8x16::default();
        for j in 0..ncols {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = U8x16::from(q);
            rng.fill_bytes(chi.as_mut());
            let [lo, hi] = q.carryless_mul_wide(chi);
            check = (check.0 ^ lo, check.1 ^ hi)
        }
        let x = channel
            .read_block()
            .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
        let t0 = channel
            .read_block()
            .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
        let t1 = channel
            .read_block()
            .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
        let [lo, hi] = x.carryless_mul_wide(self.ot.s_);
        let check = (check.0 ^ lo, check.1 ^ hi);
        ensure!(
            check == (t0, t1),
            ErrorKind::OtherError,
            "Consistency check failed"
        );
        Ok(qs)
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> FixedKeyInitializer for Sender<OT> {
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self> {
        let ot = AlszSender::<OT>::init_fixed_key(channel, s_, rng)?;
        Ok(Self { ot })
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> OtSender for Sender<OT> {
    type Msg = U8x16;

    fn init<C: AbstractChannel, RNG: CryptoRng>(channel: &mut C, rng: &mut RNG) -> Result<Self> {
        let ot = AlszSender::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[(U8x16, U8x16)],
        rng: &mut RNG,
    ) -> Result<()> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m, rng)?;
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = U8x16::from(q);
            let y0 =
                TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128) ^ input.0;
            let q = q ^ self.ot.s_;
            let y1 =
                TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128) ^ input.1;
            channel
                .write_u8x16(&y0)
                .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
            channel
                .write_u8x16(&y1)
                .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
        }
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> CorrelatedSender for Sender<OT> {
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        m: usize,
        delta: Self::Msg,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>> {
        let qs = self.send_setup(channel, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = U8x16::from(q);
            let x0 = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);
            let x1 = x0 ^ delta;
            let q = q ^ self.ot.s_;
            let y = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128) ^ x1;
            channel
                .write_u8x16(&y)
                .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
            out.push(x0);
        }
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> RandomSender for Sender<OT> {
    fn send_random<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>> {
        let qs = self.send_setup(channel, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = U8x16::from(q);
            let x0 = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);
            let q = q ^ self.ot.s_;
            let x1 = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> std::fmt::Display for Sender<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS Sender")
    }
}

impl<OT: OtSender<Msg = U8x16> + Malicious> Receiver<OT> {
    pub(super) fn receive_setup<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[F2],
        rng: &mut RNG,
    ) -> Result<Vec<u8>> {
        let m = inputs.len();
        let m = if !m.is_multiple_of(8) {
            m + (8 - m % 8)
        } else {
            m
        };
        let m_ = m + 128 + SSP;
        // Capacity of r is the number of bytes needed to hold m_,
        // plus enough extra bytes to split those bytes evenly into
        // 8-byte words.
        let mut r = Vec::with_capacity(if (m_ / 8).is_multiple_of(8) {
            m_ / 8
        } else {
            m_ / 8 + (8 - (m_ / 8) % 8)
        });
        F2BitSerializer::new(&mut std::io::empty())
            .wrap_err(
                ErrorKind::SerializationError,
                "Could not initialize bit serializer",
            )?
            .write_vec(
                &mut r,
                inputs
                    .iter()
                    .copied()
                    .chain((0..(m_ - m)).map(|_| rand::random::<F2>())),
            )
            .wrap_err(ErrorKind::SerializationError, "Failed to write bits")?;
        let ts = self.ot.receive_setup(channel, &r, m_)?;
        // Check correlation
        let mut seed = U8x16::default();
        rng.fill_bytes(seed.as_mut());
        let seed = swanky_cointoss::receive(channel, &[seed])
            .wrap_err(ErrorKind::NetworkError, "Unable to receive cointoss")?;
        let mut rng = SwankyRng::from_seed(seed[0]);
        let mut x = U8x16::default();
        let mut t = (U8x16::default(), U8x16::default());
        let r_ = F2BitDeserializer::new(&mut std::io::empty())
            .wrap_err(
                ErrorKind::SerializationError,
                "Could not initialize bit deserializer",
            )?
            .read_vec(&mut &r[..], m_)
            .wrap_err(ErrorKind::SerializationError, "Failed to read bits")?;
        let mut chi = U8x16::default();
        for (j, xj) in r_.into_iter().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj: [u8; 16] = tj.try_into().unwrap();
            let tj = U8x16::from(tj);
            rng.fill_bytes(chi.as_mut());
            x ^= if xj.into() { chi } else { U8x16::default() };
            let [lo, hi] = tj.carryless_mul_wide(chi);
            t = (t.0 ^ lo, t.1 ^ hi);
        }
        channel
            .write_u8x16(&x)
            .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
        channel
            .write_u8x16(&t.0)
            .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
        channel
            .write_u8x16(&t.1)
            .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
        Ok(ts)
    }
}

impl<OT: OtSender<Msg = U8x16> + Malicious> OtReceiver for Receiver<OT> {
    type Msg = U8x16;

    fn init<C: AbstractChannel, RNG: CryptoRng>(channel: &mut C, rng: &mut RNG) -> Result<Self> {
        let ot = AlszReceiver::<OT>::init(channel, rng)?;
        Ok(Self { ot })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[F2],
        rng: &mut RNG,
    ) -> Result<Vec<U8x16>> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        // Output result
        let mut out = Vec::with_capacity(inputs.len());
        for (j, &b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y0 = channel
                .read_block()
                .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
            let y1 = channel
                .read_block()
                .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
            let y = if b.into() { y1 } else { y0 };
            let y = y ^ TweakableCircularCorrelationRobustHash::fixed_key()
                .hash(U8x16::from(t), j as u128);
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = U8x16> + Malicious> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[F2],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, &b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = channel
                .read_block()
                .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
            let y = if b.into() { y } else { U8x16::default() };
            let h =
                TweakableCircularCorrelationRobustHash::fixed_key().hash(U8x16::from(t), j as u128);
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = U8x16> + Malicious> RandomReceiver for Receiver<OT> {
    fn receive_random<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[F2],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>> {
        let ts = self.receive_setup(channel, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let h =
                TweakableCircularCorrelationRobustHash::fixed_key().hash(U8x16::from(t), j as u128);
            out.push(h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = U8x16> + Malicious> std::fmt::Display for Receiver<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "KOS Receiver")
    }
}

impl<OT: OtReceiver<Msg = U8x16> + Malicious> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = U8x16> + Malicious> SemiHonest for Receiver<OT> {}
impl<OT: OtReceiver<Msg = U8x16> + Malicious> Malicious for Sender<OT> {}
impl<OT: OtSender<Msg = U8x16> + Malicious> Malicious for Receiver<OT> {}

#[test]
fn test_functionality() {
    let ninputs = 1 << 10;
    swanky_ot_test::test_otext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_cotext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_rotext::<Sender, Receiver>(ninputs);
    let ninputs = (1 << 10) + 1;
    swanky_ot_test::test_otext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_cotext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_rotext::<Sender, Receiver>(ninputs);
}
