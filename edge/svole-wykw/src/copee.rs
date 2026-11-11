//! Implementation of the Weng-Yang-Katz-Wang COPEe protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 15).

use super::utils::Powers;
use hybrid_array::{Array, typenum::Unsigned};
use rand::CryptoRng;
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};
use swanky_adversary::Malicious;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::{Degree, FiniteField as FF, FiniteRing};
use swanky_field_binary::F2;
use swanky_ot_kos::KOS;
use swanky_ot_traits_new::{OTRandom, Receiver as OtReceiver, Sender as OtSender};
use swanky_party::{either::PartyEither, ty_eq::Witness};
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

pub(super) struct Sender<ROT: OTRandom<OtSender> + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    aes_objs: Vec<(Aes128EncryptOnly, Aes128EncryptOnly)>,
    pows: Powers<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

pub(super) struct Receiver<ROT: OTRandom<OtReceiver> + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: Array<F2, FE::NumberOfBitsInBitDecomposition>,
    aes_objs: Vec<Aes128EncryptOnly>,
    pows: Powers<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

pub(super) type CopeeSender<FE> = Sender<KOS<OtSender>, FE>;
pub(super) type CopeeReceiver<FE> = Receiver<KOS<OtReceiver>, FE>;

// Uses `Aes128EncryptOnly` as a pseudo-random function.
fn prf<FE: FF>(aes: &Aes128EncryptOnly, pt: U8x16) -> FE::PrimeField {
    let seed = aes.encrypt(pt);
    FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(seed))
}

impl<ROT: OTRandom<OtSender> + Malicious, FE: FF> Sender<ROT, FE> {
    pub(super) fn init<RNG: CryptoRng>(
        channel: &mut Channel,
        pows: Powers<FE>,
        mut rng: &mut RNG,
    ) -> Result<Self> {
        let mut ot = ROT::init(channel, &mut rng)?;
        let nbits = <FE::PrimeField as FF>::NumberOfBitsInBitDecomposition::USIZE;
        let r = Degree::<FE>::USIZE;
        let mut keys = Vec::with_capacity(nbits * r);
        ot.ot_random(
            PartyEither::new(Witness::EQUAL_TYPES, nbits * r),
            &mut keys,
            channel,
            rng,
        )?;

        let aes_objs: Vec<(Aes128EncryptOnly, Aes128EncryptOnly)> = keys
            .iter()
            .map(|keys| {
                let [k0, k1] = keys.as_ref().into_inner(Witness::EQUAL_TYPES);
                (
                    Aes128EncryptOnly::new_with_key(*k0),
                    Aes128EncryptOnly::new_with_key(*k1),
                )
            })
            .collect();
        let mut acc = FE::ONE;
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut() {
            *item = acc;
            acc *= two;
        }
        Ok(Self {
            _ot: PhantomData::<ROT>,
            aes_objs,
            nbits,
            pows,
            twos,
            counter: 0,
        })
    }

    pub(super) fn send(&mut self, channel: &mut Channel, input: &FE::PrimeField) -> Result<FE> {
        let pt = U8x16::from(self.counter as u128);
        let mut w = FE::ZERO;
        for (i, pow) in self.pows.get().iter().enumerate() {
            let mut sum = FE::ZERO;
            for (j, two) in self.twos.iter().enumerate() {
                let (prf0, prf1) = &self.aes_objs[i * self.nbits + j];
                let w0 = prf::<FE>(prf0, pt);
                let w1 = prf::<FE>(prf1, pt);
                sum += w0 * *two;
                channel.write(&(w0 - w1 - *input))?;
            }
            w += sum * *pow;
        }
        self.counter += 1;
        Ok(w)
    }
}

impl<ROT: OTRandom<OtReceiver> + Malicious, FE: FF> Receiver<ROT, FE> {
    pub(super) fn init_with_picked_delta<RNG: CryptoRng>(
        channel: &mut Channel,
        pows: Powers<FE>,
        mut rng: &mut RNG,
        delta: FE,
    ) -> Result<Self> {
        let nbits = <FE::PrimeField as FF>::NumberOfBitsInBitDecomposition::USIZE;
        let mut ot = ROT::init(channel, &mut rng)?;
        let choices = delta.bit_decomposition().map(|b| b.into());
        let mut acc = FE::ONE;
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut().take(nbits) {
            *item = acc;
            acc *= two;
        }
        let mut keys = Vec::with_capacity(choices.len());
        ot.ot_random(
            PartyEither::new(Witness::EQUAL_TYPES, &choices[..]),
            &mut keys,
            channel,
            rng,
        )?;
        let aes_objs = keys
            .iter()
            .map(|k| Aes128EncryptOnly::new_with_key(*k.as_ref().into_inner(Witness::EQUAL_TYPES)))
            .collect();
        Ok(Self {
            _ot: PhantomData::<ROT>,
            delta,
            choices,
            pows,
            twos,
            aes_objs,
            nbits,
            counter: 0,
        })
    }
    pub(super) fn init<RNG: CryptoRng>(
        channel: &mut Channel,
        pows: Powers<FE>,
        mut rng: &mut RNG,
    ) -> Result<Self> {
        let delta = FE::random(&mut rng);
        Self::init_with_picked_delta(channel, pows, rng, delta)
    }

    pub(super) fn delta(&self) -> FE {
        self.delta
    }

    pub(super) fn receive(&mut self, channel: &mut Channel) -> Result<FE> {
        let pt = U8x16::from(self.counter as u128);
        let mut res = FE::ZERO;
        for (j, pow) in self.pows.get().iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let w = prf::<FE>(&self.aes_objs[j * self.nbits + k], pt);
                let mut tau = channel.read::<FE::PrimeField>()?;
                let choice = Choice::from(u8::from(self.choices[j + k]));
                tau += w;
                let v = FE::PrimeField::conditional_select(&w, &tau, choice);
                sum += v * *two;
            }
            res += sum * *pow;
        }
        self.counter += 1;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::utils::Powers, CopeeReceiver, CopeeSender};
    use swanky_channel::local::local_channel_pair;
    use swanky_field::FiniteField as FF;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F2, F128b};
    use swanky_field_f61p::F61p;
    use swanky_rng::SwankyRng;

    fn test_copee_<FE: FF>(len: usize) {
        let ((input, ws), (copee_receiver, vs)) = local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let input = FE::PrimeField::random(&mut rng);
                let pows = <Powers<_> as Default>::default();
                let mut copee_sender = CopeeSender::<FE>::init(c, pows, &mut rng).unwrap();
                let ws: Vec<FE> = (0..len)
                    .map(|_| copee_sender.send(c, &input).unwrap())
                    .collect();
                Ok((input, ws))
            },
            |c| {
                let mut rng = SwankyRng::new();
                let pows = <Powers<_> as Default>::default();
                let mut copee_receiver = CopeeReceiver::<FE>::init(c, pows, &mut rng).unwrap();
                let vs: Vec<FE> = (0..len)
                    .map(|_| copee_receiver.receive(c).unwrap())
                    .collect();
                Ok((copee_receiver, vs))
            },
        )
        .unwrap();

        for (w, v) in ws.iter().zip(vs.iter()) {
            let mut delta = input * copee_receiver.delta();
            delta += *v;
            assert_eq!(*w, delta);
        }
    }

    #[test]
    fn test_copee() {
        test_copee_::<F128b>(128);
        test_copee_::<F2>(128);
        test_copee_::<F61p>(128);
    }
}
