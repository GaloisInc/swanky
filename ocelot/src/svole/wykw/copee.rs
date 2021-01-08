// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang COPEe protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 15).

use crate::{
    errors::Error,
    ot::{KosReceiver, KosSender, RandomReceiver as ROTReceiver, RandomSender as ROTSender},
};
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{
    field::FiniteField as FF, utils::unpack_bits, AbstractChannel, Aes128, Block, Malicious,
};
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};

/// COPEe sender.
pub struct Sender<'a, ROT: ROTSender + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    aes_objs: Vec<(Aes128, Aes128)>,
    pows: &'a [FE],
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

/// COPEe receiver.
pub struct Receiver<'a, ROT: ROTReceiver + Malicious, FE: FF> {
    _ot: PhantomData<ROT>,
    delta: FE,
    choices: Vec<bool>,
    aes_objs: Vec<Aes128>,
    pows: &'a [FE],
    twos: Vec<FE>,
    nbits: usize,
    counter: u64,
}

/// Aliasing COPEe sender.
pub type CopeeSender<'a, FE> = Sender<'a, KosSender, FE>;
/// Aliasing COPEe receiver.
pub type CopeeReceiver<'a, FE> = Receiver<'a, KosReceiver, FE>;

/// `Aes128` as a pseudo-random function.
fn prf<FE: FF>(aes: &Aes128, pt: Block) -> FE::PrimeField {
    let seed = aes.encrypt(pt);
    FE::PrimeField::from_uniform_bytes(&<[u8; 16]>::from(seed))
}

/// Implement CopeeSender for Sender type
impl<'a, ROT: ROTSender<Msg = Block> + Malicious, FE: FF> Sender<'a, ROT, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: &'a [FE],
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = ROT::init(channel, &mut rng)?;
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let keys = ot.send_random(channel, nbits * r, &mut rng)?;
        let aes_objs: Vec<(Aes128, Aes128)> = keys
            .iter()
            .map(|(k0, k1)| (Aes128::new(*k0), Aes128::new(*k1)))
            .collect();
        let mut acc = FE::ONE;
        // `two` can be computed by adding `FE::ONE` to itself. For example, the
        // field `F2` has only two elements `0` and `1` and `two` becomes `0` as
        // `1 + 1 = 0` in this field.
        let two = FE::ONE + FE::ONE;
        let mut twos = vec![FE::ZERO; nbits];
        for item in twos.iter_mut().take(nbits) {
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

    /// Runs COPEe extend on a prime field element `u` and returns an extended
    /// field element `w` such that `w = u'Δ + v` holds, where `u'` is result of
    /// the conversion from `u` to the extended field element.
    pub fn send<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        input: &FE::PrimeField,
    ) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut w = FE::ZERO;
        for (j, pow) in self.pows.iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let (prf0, prf1) = &self.aes_objs[j * self.nbits + k];
                let w0 = prf::<FE>(prf0, pt);
                let w1 = prf::<FE>(prf1, pt);
                sum += two.multiply_by_prime_subfield(w0);
                channel.write_fe(w0 - w1 - *input)?;
            }
            //channel.flush()?;
            sum *= *pow;
            w += sum;
        }
        self.counter += 1;
        Ok(w)
    }
}

/// Implement CopeeReceiver for Receiver type.
impl<'a, ROT: ROTReceiver<Msg = Block> + Malicious, FE: FF> Receiver<'a, ROT, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: &'a [FE],
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let nbits = 128 - (FE::MODULUS - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut ot = ROT::init(channel, &mut rng)?;
        let delta = FE::random(&mut rng);
        let choices = unpack_bits(delta.to_bytes().as_slice(), nbits * r);
        let mut acc = FE::ONE;
        // `two` can be computed by adding `FE::ONE` to itself. For example, the field `F2` has only two elements `0` and `1`
        // and `two` becomes `0` as `1 + 1 = 0` in this field.
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
    /// Returns the receiver choice `Δ`.
    pub fn delta(&self) -> FE {
        self.delta
    }

    /// Runs COPEe extend and returns a field element `v` such that `w = u'Δ + v` holds.
    pub fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<FE, Error> {
        let pt = Block::from(self.counter as u128);
        let mut res = FE::ZERO;
        for (j, pow) in self.pows.iter().enumerate() {
            let mut sum = FE::ZERO;
            for (k, two) in self.twos.iter().enumerate() {
                let w = prf::<FE>(&self.aes_objs[j * self.nbits + k], pt);
                let mut tau = channel.read_fe::<FE::PrimeField>()?;
                let choice = Choice::from(self.choices[j + k] as u8);
                tau += w;
                let v = FE::PrimeField::conditional_select(&w, &tau, choice);
                sum += two.multiply_by_prime_subfield(v);
            }
            sum *= *pow;
            res += sum;
        }
        self.counter += 1;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{CopeeReceiver, CopeeSender};
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_copee_<FE: FF + Send>(len: usize) {
        let mut rng = AesRng::new();
        let input = FE::PrimeField::random(&mut rng);
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = super::super::utils::gen_pows();
            let mut copee_sender = CopeeSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            let ws: Vec<FE> = (0..len)
                .map(|_| copee_sender.send(&mut channel, &input).unwrap())
                .collect();
            ws
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = super::super::utils::gen_pows();
        let mut copee_receiver = CopeeReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let vs: Vec<FE> = (0..len)
            .map(|_| copee_receiver.receive(&mut channel).unwrap())
            .collect();
        let ws = handle.join().unwrap();
        for (w, v) in ws.iter().zip(vs.iter()) {
            let mut delta = copee_receiver.delta().multiply_by_prime_subfield(input);
            delta += *v;
            assert_eq!(*w, delta);
        }
    }

    #[test]
    fn test_copee() {
        test_copee_::<Fp>(128);
        test_copee_::<Gf128>(128);
        test_copee_::<F2>(128);
        test_copee_::<F61p>(128);
    }
}
