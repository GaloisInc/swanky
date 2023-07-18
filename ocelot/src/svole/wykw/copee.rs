//! Implementation of the Weng-Yang-Katz-Wang COPEe protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 15).

use super::utils::Powers;
use crate::{
    errors::Error,
    ot::{KosReceiver, KosSender, RandomReceiver as ROTReceiver, RandomSender as ROTSender},
};
use generic_array::{typenum::Unsigned, GenericArray};
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{Degree, FiniteField as FF},
    ring::FiniteRing,
    AbstractChannel, Aes128, Block, Malicious,
};
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};

pub(super) struct Sender<ROT: ROTSender + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    aes_objs: Vec<(Aes128, Aes128)>,
    pows: Powers<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

pub(super) struct Receiver<ROT: ROTReceiver + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: GenericArray<bool, FE::NumberOfBitsInBitDecomposition>,
    aes_objs: Vec<Aes128>,
    pows: Powers<FE>,
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

pub(super) type CopeeSender<FE> = Sender<KosSender, FE>;
pub(super) type CopeeReceiver<FE> = Receiver<KosReceiver, FE>;

// Uses `Aes128` as a pseudo-random function.
fn prf<FE: FF>(aes: &Aes128, pt: Block) -> FE::PrimeField {
    let seed = aes.encrypt(pt);
    FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(seed))
}

impl<ROT: ROTSender<Msg = Block> + Malicious, FE: FF> Sender<ROT, FE> {
    pub(super) fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = ROT::init(channel, &mut rng)?;
        let nbits = <FE::PrimeField as FF>::NumberOfBitsInBitDecomposition::USIZE;
        let r = Degree::<FE>::USIZE;
        let keys = ot.send_random(channel, nbits * r, &mut rng)?;
        let aes_objs: Vec<(Aes128, Aes128)> = keys
            .iter()
            .map(|(k0, k1)| (Aes128::new(*k0), Aes128::new(*k1)))
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

    pub(super) fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &FE::PrimeField,
    ) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut w = FE::ZERO;
        for (i, pow) in self.pows.get().iter().enumerate() {
            let mut sum = FE::ZERO;
            for (j, two) in self.twos.iter().enumerate() {
                let (prf0, prf1) = &self.aes_objs[i * self.nbits + j];
                let w0 = prf::<FE>(prf0, pt);
                let w1 = prf::<FE>(prf1, pt);
                sum += w0 * *two;
                channel.write_serializable(&(w0 - w1 - *input))?;
            }
            w += sum * *pow;
        }
        self.counter += 1;
        Ok(w)
    }
}

impl<ROT: ROTReceiver<Msg = Block> + Malicious, FE: FF> Receiver<ROT, FE> {
    pub(super) fn init_with_picked_delta<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        mut rng: &mut RNG,
        delta: FE,
    ) -> Result<Self, Error> {
        let nbits = <FE::PrimeField as FF>::NumberOfBitsInBitDecomposition::USIZE;
        let mut ot = ROT::init(channel, &mut rng)?;
        let choices = delta.bit_decomposition();
        let mut acc = FE::ONE;
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut().take(nbits) {
            *item = acc;
            acc *= two;
        }
        let keys = ot.receive_random(channel, &choices, &mut rng)?;
        let aes_objs = keys.iter().map(|k| Aes128::new(*k)).collect();
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
    pub(super) fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let delta = FE::random(&mut rng);
        Self::init_with_picked_delta(channel, pows, rng, delta)
    }

    pub(super) fn delta(&self) -> FE {
        self.delta
    }

    pub(super) fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut res = FE::ZERO;
        for (j, pow) in self.pows.get().iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let w = prf::<FE>(&self.aes_objs[j * self.nbits + k], pt);
                let mut tau = channel.read_serializable::<FE::PrimeField>()?;
                let choice = Choice::from(self.choices[j + k] as u8);
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
    use scuttlebutt::{
        field::{F128b, F61p, FiniteField as FF, F2},
        ring::FiniteRing,
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_copee_<FE: FF>(len: usize) {
        let mut rng = AesRng::new();
        let input = FE::PrimeField::random(&mut rng);
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = <Powers<_> as Default>::default();
            let mut copee_sender = CopeeSender::<FE>::init(&mut channel, pows, &mut rng).unwrap();
            let ws: Vec<FE> = (0..len)
                .map(|_| copee_sender.send(&mut channel, &input).unwrap())
                .collect();
            ws
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = <Powers<_> as Default>::default();
        let mut copee_receiver = CopeeReceiver::<FE>::init(&mut channel, pows, &mut rng).unwrap();
        let vs: Vec<FE> = (0..len)
            .map(|_| copee_receiver.receive(&mut channel).unwrap())
            .collect();
        let ws = handle.join().unwrap();
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
