// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of single-point sVOLE.

use super::{
    ggm_utils::{ggm, ggm_prime, GgmTemporaryStorage},
    utils::Powers,
};
use crate::svole::wykw::specialization::{
    FiniteFieldSendSpecialization, FiniteFieldSpecialization,
};
use crate::{
    errors::Error,
    ot::{KosReceiver, KosSender, Receiver as OtReceiver, Sender as OtSender},
};
use generic_array::typenum::Unsigned;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng, SeedableRng,
};
use scuttlebutt::{
    commitment::{Commitment, ShaCommitment},
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel, AesRng, Block, Malicious,
};
use std::marker::PhantomData;
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher};

pub(super) struct Sender<OT: OtReceiver + Malicious, FE: FF, S: FiniteFieldSpecialization<FE>> {
    ot: OT,
    pows: Powers<FE>,
    ggm_seeds: (Aes128EncryptOnly, Aes128EncryptOnly),
    phantom: PhantomData<S>,
}

pub(super) struct Receiver<OT: OtSender + Malicious, FE: FF, S: FiniteFieldSpecialization<FE>> {
    ot: OT,
    delta: FE,
    pows: Powers<FE>,
    ggm_seeds: (Aes128EncryptOnly, Aes128EncryptOnly),
    ggm_temporary_storage: GgmTemporaryStorage,
    phantom: PhantomData<S>,
}

pub(super) type SpsSender<FE, S> = Sender<KosReceiver, FE, S>;
pub(super) type SpsReceiver<FE, S> = Receiver<KosSender, FE, S>;

// Implementation of the EQ protocol functionality described in
// <https://eprint.iacr.org/2020/925.pdf>, Page 30.
fn eq_send<C: AbstractChannel, FE: FF>(channel: &mut C, x: FE) -> Result<bool, Error> {
    let mut com = [0u8; 32];
    channel.read_bytes(&mut com)?;

    channel.write_fe(x)?;
    channel.flush()?;

    let mut seed = [0u8; 32];
    channel.read_bytes(&mut seed)?;
    let y = channel.read_fe::<FE>()?;

    let mut commit = ShaCommitment::new(seed);
    commit.input(&y.to_bytes());
    if commit.finish() == com {
        Ok(x == y)
    } else {
        Err(Error::InvalidOpening)
    }
}

// Implementation of the EQ protocol functionality described in
// <https://eprint.iacr.org/2020/925.pdf>, Page 30.
fn eq_receive<C: AbstractChannel, RNG: CryptoRng + Rng, FE: FF>(
    channel: &mut C,
    rng: &mut RNG,
    y: FE,
) -> Result<bool, Error> {
    let seed = rng.gen::<[u8; 32]>();
    let mut h = ShaCommitment::new(seed);
    h.input(&y.to_bytes());
    let com = h.finish();

    channel.write_bytes(&com)?;
    channel.flush()?;

    let x = channel.read_fe::<FE>()?;
    if x != y {
        return Err(Error::InvalidOpening);
    }

    channel.write_bytes(&seed)?;
    channel.write_fe(y)?;
    channel.flush()?;

    Ok(x == y)
}

impl<OT: OtReceiver<Msg = Block> + Malicious, FE: FF, S: FiniteFieldSendSpecialization<FE>>
    Sender<OT, FE, S>
{
    pub(super) fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, rng)?;
        let seed0 = rng.gen::<Block>();
        let seed1 = rng.gen::<Block>();
        let seeds = scuttlebutt::cointoss::send(channel, &[seed0, seed1])?;
        let aes0 = Aes128EncryptOnly::new_with_key(seeds[0].0);
        let aes1 = Aes128EncryptOnly::new_with_key(seeds[1].0);
        Ok(Self {
            pows,
            ot,
            ggm_seeds: (aes0, aes1),
            phantom: PhantomData,
        })
    }

    pub(super) fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        n: usize,                             // Equal to cols / weight
        base_voles: &[S::SenderPairContents], // Equals to weight + r
        mut rng: &mut RNG,
    ) -> Result<Vec<S::SenderPairContents>, Error> {
        debug_assert!(
            (n as u128 - 1).leading_zeros() + (n as u128).trailing_zeros() == 128,
            "expected power of 2, instead found: {}",
            n
        );
        let nbits = 128 - (n as u128 - 1).leading_zeros() as usize;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let total_len = base_voles.len();
        let base_uws = &base_voles[0..total_len - r];
        let base_consistency = &base_voles[total_len - r..];
        let t = base_uws.len();
        let mut result = vec![S::new_sender_pair(FE::PrimeField::ZERO, FE::ZERO); n * t];
        let mut betas = Vec::with_capacity(t);

        for (a, _) in base_uws.iter().copied().map(S::extract_sender_pair) {
            let beta = FE::PrimeField::random_nonzero(&mut rng);
            let a_prime = beta - a;
            channel.write_fe(a_prime)?;
            betas.push(beta);
        }
        let distribution = Uniform::from(0..n);
        let mut alphas = Vec::with_capacity(t);
        let mut choices = Vec::with_capacity(t * nbits);
        for _ in 0..t {
            let alpha = distribution.sample(&mut rng);
            let mut choices_ = unpack_bits(&(!alpha).to_le_bytes(), nbits);
            choices_.reverse(); // to get the first bit as MSB.
            choices.extend(choices_);
            alphas.push(alpha);
        }

        let keys = self.ot.receive(channel, &choices, rng)?;

        for (i, ((_, w), (alpha, beta))) in base_uws
            .iter()
            .copied()
            .map(S::extract_sender_pair)
            .zip(alphas.iter().zip(betas.into_iter()))
            .enumerate()
        {
            let sum = ggm_prime::<FE, S>(
                *alpha,
                bytemuck::cast_slice(&keys[i * nbits..(i + 1) * nbits]),
                &self.ggm_seeds,
                &mut result[i * n..(i + 1) * n],
            );
            let d: FE = channel.read_fe()?;
            result[i * n + alpha] = S::new_sender_pair(beta, w - (d + sum));
        }

        self.send_batch_consistency_check(channel, &result, &base_consistency, rng)?;

        Ok(result)
    }

    #[inline(always)]
    fn send_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        uws: &[S::SenderPairContents],      // length = m * t = n
        base_uws: &[S::SenderPairContents], // length = r
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        // Generate `chi`s from seed and send seed to receiver at the end.
        let seed = rng.gen::<Block>();
        let mut rng_chi = AesRng::from_seed(seed);
        let mut va = FE::ZERO;
        let mut x_stars = vec![FE::PrimeField::ZERO; r];
        for (u, w) in uws.iter().copied().map(S::extract_sender_pair) {
            let chi = FE::random(&mut rng_chi);
            va += chi * w;
            // There will be one, and exactly one, `u` (= `β`) which is
            // non-zero. Don't `break` after we hit this one to avoid a
            // potential side-channel attack.
            if u != FE::PrimeField::ZERO {
                for (x, y) in x_stars
                    .iter_mut()
                    .zip(chi.to_polynomial_coefficients().into_iter())
                {
                    *x += u * y;
                }
            }
        }
        for (pows, (x_star, (u, w))) in self.pows.get().iter().zip(
            x_stars
                .iter()
                .zip(base_uws.iter().copied().map(S::extract_sender_pair)),
        ) {
            channel.write_fe(*x_star - u)?;
            va -= *pows * w;
        }
        channel.write_block(&seed)?;
        channel.flush()?;

        let b = eq_send(channel, va)?;
        if b {
            Ok(())
        } else {
            Err(Error::EqCheckFailed)
        }
    }

    pub(super) fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, rng)?;
        Ok(Self {
            ot,
            pows: self.pows.clone(),
            ggm_seeds: self.ggm_seeds.clone(),
            phantom: PhantomData,
        })
    }
}

impl<OT: OtSender<Msg = Block> + Malicious, FE: FF, S: FiniteFieldSpecialization<FE>>
    Receiver<OT, FE, S>
{
    pub(super) fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        delta: FE,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, &mut rng)?;
        let seed0 = rng.gen::<Block>();
        let seed1 = rng.gen::<Block>();
        let seeds = scuttlebutt::cointoss::receive(channel, &[seed0, seed1])?;
        let aes0 = Aes128EncryptOnly::new_with_key(seeds[0].0);
        let aes1 = Aes128EncryptOnly::new_with_key(seeds[1].0);
        Ok(Self {
            pows,
            delta,
            ot,
            ggm_seeds: (aes0, aes1),
            ggm_temporary_storage: Default::default(),
            phantom: PhantomData,
        })
    }

    pub(super) fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        n: usize,
        base_voles: &[FE], // Length equals weight + r
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let total_len = base_voles.len();
        let vs = &base_voles[0..total_len - r];
        let base_consistency = &base_voles[total_len - r..];
        let nbits = 128 - (n as u128 - 1).leading_zeros() as usize;
        let t = vs.len();
        let mut gammas = Vec::with_capacity(t);
        let mut result = vec![FE::ZERO; n * t];
        for v in vs.iter() {
            let a_prime = channel.read_fe::<FE::PrimeField>()?;
            let gamma = *v - self.delta.multiply_by_prime_subfield(a_prime);
            gammas.push(gamma);
        }
        let mut keys = Vec::with_capacity(t * nbits);
        for i in 0..t {
            let seed = rng.gen::<Block>().0;
            ggm(
                nbits,
                seed,
                &self.ggm_seeds,
                &mut result[i * n..(i + 1) * n],
                &mut keys,
                &mut self.ggm_temporary_storage,
            );
        }
        debug_assert_eq!(keys.len(), t * nbits);
        self.ot.send(channel, &keys, rng)?;
        for (i, gamma) in gammas.into_iter().enumerate() {
            let d = gamma - result[i * n..(i + 1) * n].iter().map(|v| *v).sum();
            channel.write_fe(d)?;
        }
        channel.flush()?;

        self.receive_batch_consistency_check(channel, &result, &base_consistency, rng)?;
        Ok(result)
    }

    #[inline(always)]
    fn receive_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        vs: &[FE],
        y_stars: &[FE],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut x_stars: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
        for item in x_stars.iter_mut() {
            *item = channel.read_fe()?;
        }
        let y = self
            .pows
            .get()
            .iter()
            .zip(x_stars.into_iter().zip(y_stars.iter()))
            .map(|(pow, (x, y))| (*y - self.delta.multiply_by_prime_subfield(x)) * *pow)
            .sum();
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        let mut vb = FE::ZERO;
        for v in vs.iter() {
            vb += *v * FE::random(&mut rng_chi);
        }
        vb -= y;
        let res = eq_receive(channel, rng, vb)?;
        if res {
            Ok(())
        } else {
            Err(Error::EqCheckFailed)
        }
    }

    pub(super) fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, rng)?;
        Ok(Self {
            ot,
            delta: self.delta,
            pows: self.pows.clone(),
            ggm_seeds: self.ggm_seeds.clone(),
            ggm_temporary_storage: Default::default(),
            phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{
            base_svole::{Receiver as BaseReceiver, Sender as BaseSender},
            utils::Powers,
        },
        SpsReceiver, SpsSender,
    };
    use crate::svole::wykw::specialization::{
        FiniteFieldSendSpecialization, Gf40Specialization, NoSpecialization,
    };
    use generic_array::typenum::Unsigned;
    use scuttlebutt::field::Gf40;
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Gf128},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_spsvole_<FE: FF, S: FiniteFieldSendSpecialization<FE>>(cols: usize, weight: usize) {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let n = cols / weight;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = <Powers<_> as Default>::default();
            let mut base = BaseSender::<FE, S>::init(&mut channel, pows.clone(), &mut rng).unwrap();
            let uw = base.send(&mut channel, weight + r, &mut rng).unwrap();
            let mut spsvole = SpsSender::<FE, S>::init(&mut channel, pows, &mut rng).unwrap();
            spsvole
                .send(&mut channel, n, &uw[0..weight + r], &mut rng)
                .unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = <Powers<_> as Default>::default();
        let mut base = BaseReceiver::<FE>::init(&mut channel, pows.clone(), &mut rng).unwrap();
        let v = base.receive(&mut channel, weight + r, &mut rng).unwrap();
        let mut spsvole =
            SpsReceiver::<FE, S>::init(&mut channel, pows, base.delta(), &mut rng).unwrap();
        let vs = spsvole
            .receive(&mut channel, n, &v[0..weight + r], &mut rng)
            .unwrap();
        let uws = handle.join().unwrap();
        for i in 0..weight {
            for j in 0..n {
                let right = base
                    .delta()
                    .multiply_by_prime_subfield(S::extract_sender_pair(uws[i * n + j]).0)
                    + vs[i * n + j];
                assert_eq!(S::extract_sender_pair(uws[i * n + j]).1, right);
            }
        }
    }

    #[test]
    fn test_spsvole_gf128() {
        let cols = 10_805_248;
        let weight = 1_319;

        test_spsvole_::<Gf128, NoSpecialization>(cols, weight);
    }

    #[test]
    fn test_spsvole_f61p() {
        let cols = 10_805_248;
        let weight = 1_319;

        test_spsvole_::<F61p, NoSpecialization>(cols, weight);
    }

    #[test]
    fn test_spsvole_gf40() {
        let cols = 10_805_248;
        let weight = 1_319;

        test_spsvole_::<Gf40, Gf40Specialization>(cols, weight);
    }
}
