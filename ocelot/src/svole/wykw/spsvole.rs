// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of single-point svole protocol.

use super::ggm_utils::{ggm, ggm_prime};
use crate::{
    errors::Error,
    ot::{KosReceiver, KosSender, Receiver as OtReceiver, Sender as OtSender},
};
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_core::RngCore;
use scuttlebutt::{
    commitment::{Commitment, ShaCommitment},
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel, AesRng, Block, Malicious,
};

/// SpsVole Sender.
pub struct Sender<OT: OtReceiver, FE: FF> {
    ot: OT,
    pows: Vec<FE>,
}

/// SpsVole Receiver.
pub struct Receiver<OT: OtSender, FE: FF> {
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
}
/// Alias for SpsVole Sender.
pub type SpsSender<FE> = Sender<KosReceiver, FE>;
/// Alias for SpsVole Receiver.
pub type SpsReceiver<FE> = Receiver<KosSender, FE>;

/// Implementation of the EQ protocol functionality described in the write-up (<https://eprint.iacr.org/2020/925.pdf>, Page 30)
/// Implementation of sender functionality
/// TODO: Channel is going to be out of sync if sender receives commit of vb before sending va out.
fn eq_send<C: AbstractChannel, FE: FF>(channel: &mut C, input: &FE) -> Result<bool, Error> {
    let va = *input;
    channel.write_fe(va)?;
    channel.flush()?;
    let mut comm_vb = [0u8; 32];
    channel.read_bytes(&mut comm_vb)?;
    let mut seed = [0u8; 32];
    channel.read_bytes(&mut seed)?;
    let vb = channel.read_fe::<FE>()?;
    let mut commit = ShaCommitment::new(seed);
    commit.input(&vb.to_bytes());
    let res = commit.finish();
    if res == comm_vb {
        Ok(va == vb)
    } else {
        Err(Error::InvalidOpening)
    }
}

/// Implementation of receiver functionality
fn eq_receive<C: AbstractChannel, RNG: CryptoRng + RngCore, FE: FF>(
    channel: &mut C,
    rng: &mut RNG,
    input: &FE,
) -> Result<bool, Error> {
    let vb = *input;
    let va = channel.read_fe::<FE>()?;
    let seed = rng.gen::<[u8; 32]>();
    let mut commit = ShaCommitment::new(seed);
    commit.input(&vb.to_bytes());
    let result = commit.finish();
    channel.write_bytes(&result)?;
    channel.write_bytes(&seed)?;
    channel.write_fe(vb)?;
    channel.flush()?;
    Ok(va == vb)
}

/// Implement SpsVoleSender for Sender type.
impl<OT: OtReceiver<Msg = Block> + Malicious, FE: FF> Sender<OT, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: Vec<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, rng)?;
        Ok(Self { pows, ot })
    }
    /// Runs single-point svole and outputs pair of vectors `(u, w)` such that
    /// the correlation `w = u'Δ + v` holds. Note that `u'` is the converted
    /// vector from `u` to the vector of elements of the extended field `FE`.
    /// For simplicity, the vector length `n` assumed to be a multiple of `2` as
    /// it represents the number of leaves in the GGM tree and should match with
    /// the receiver input length.
    pub fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        m: usize,                     // Equal to cols / weight
        uws: &[(FE::PrimeField, FE)], // Equals to weight
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        debug_assert!(m % 2 == 0);
        let depth = 128 - (m as u128 - 1).leading_zeros() as usize;
        let t = uws.len();
        let mut result = vec![(FE::PrimeField::ZERO, FE::ZERO); m * t];
        let mut betas = Vec::with_capacity(t);
        for (a, _) in uws.iter() {
            let mut beta = FE::PrimeField::random(&mut rng);
            while beta == FE::PrimeField::ZERO {
                beta = FE::PrimeField::random(&mut rng);
            }
            let a_prime = beta - *a;
            channel.write_fe(a_prime)?;
            betas.push(beta);
        }
        channel.flush()?;
        // Generate seeds for GGM "PRGs" and send them over the wire.
        //
        // XXX is this secure? I think so, assuming AES as no weak keys....
        // might be better to do coin flipping here though...
        let seed0 = rng.gen::<Block>();
        let seed1 = rng.gen::<Block>();
        channel.write_block(&seed0)?;
        channel.write_block(&seed1)?;
        let mut tmps = Vec::with_capacity(t);
        for (i, beta) in betas.into_iter().enumerate() {
            let alpha = rng.gen_range(0, m);
            result[i * m + alpha].0 = beta;
            let mut choices_ = unpack_bits(&(!alpha).to_le_bytes(), depth);
            choices_.reverse(); // to get the first bit as MSB.
            let keys = self.ot.receive(channel, &choices_, rng)?;
            let vs: Vec<FE> = ggm_prime(alpha, &keys, (seed0, seed1));
            for (j, item) in vs.iter().enumerate().take(m) {
                if j != alpha {
                    result[i * m + j].1 = *item;
                }
            }
            let sum = vs.into_iter().sum();
            tmps.push((alpha, sum));
        }
        for (i, ((_, delta), (alpha, sum))) in uws.iter().zip(tmps.into_iter()).enumerate() {
            let d: FE = channel.read_fe()?;
            result[i * m + alpha].1 = *delta - (d + sum);
        }
        Ok(result)
    }
    /// Batch consistency check that can be called after bunch of iterations.
    pub fn send_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        _n: usize,
        uws: &[(FE::PrimeField, FE)],      // length = t
        base_uws: &[(FE::PrimeField, FE)], // length = r
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        // Generate `chis` from seed and send seed to receiver.
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        let mut rng_chi = AesRng::from_seed(seed);
        let mut va = FE::ZERO;
        let mut x_stars = vec![FE::PrimeField::ZERO; r];
        for (u, w) in uws.iter() {
            let chi = FE::random(&mut rng_chi);
            va += chi * *w;
            // There will be one, and exactly one, `u` (= `β`) which is
            // non-zero. Don't `break` after we hit this one to avoid a
            // potential side-channel attack.
            if *u != FE::PrimeField::ZERO {
                for (x, y) in x_stars
                    .iter_mut()
                    .zip(chi.to_polynomial_coefficients().iter())
                {
                    *x += *u * *y;
                }
            }
        }
        for (pows, (x_star, (u, w))) in self.pows.iter().zip(x_stars.iter().zip(base_uws.iter())) {
            channel.write_fe(*x_star - *u)?;
            va -= *pows * *w;
        }
        let b = eq_send(channel, &va)?;
        if b {
            Ok(())
        } else {
            Err(Error::EqCheckFailed)
        }
    }
}

/// Implement SpsVoleReceiver for Receiver type.
impl<OT: OtSender<Msg = Block> + Malicious, FE: FF> Receiver<OT, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: Vec<FE>,
        delta: FE,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, &mut rng)?;
        Ok(Self { pows, delta, ot })
    }

    /// Runs single-point svole and outputs a vector `v` such that
    /// the correlation `w = u'Δ + v` holds. Again, `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. Of course, the argument `nleaves`
    /// is suppose to be in multiples of `2` as it represents the number of
    /// leaves in the GGM tree and should match with the sender input length.
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        n: usize,
        vs: &[FE], // Length equals weight
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        assert!(n % 2 == 0);
        let depth = 128 - (n as u128 - 1).leading_zeros() as usize;
        let t = vs.len();
        let mut gammas = Vec::with_capacity(t);
        let mut ds = Vec::with_capacity(t);
        let mut result = vec![FE::ZERO; n * t];
        for (_, b) in vs.iter().enumerate() {
            let a_prime = channel.read_fe::<FE::PrimeField>()?;
            let gamma = *b - self.delta.multiply_by_prime_subfield(a_prime);
            gammas.push(gamma);
        }
        let seed0 = channel.read_block()?;
        let seed1 = channel.read_block()?;
        for (i, gamma) in gammas.into_iter().enumerate() {
            let seed = rng.gen::<Block>();
            let keys_ = ggm(depth, seed, (seed0, seed1), &mut result[i * n..(i + 1) * n]);
            // XXX hmm I would have thought batching OTs would make things more
            // efficient, but that doesn't seem to be the case. Probably needs
            // further investigation.
            self.ot.send(channel, &keys_, rng)?;
            let d = gamma - result[i * n..(i + 1) * n].iter().map(|v| *v).sum();
            ds.push(d);
        }
        for d in ds.into_iter() {
            channel.write_fe(d)?;
        }
        channel.flush()?;
        Ok(result)
    }
    /// Batch consistency check that can be called after bunch of iterations.
    pub fn receive_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        _n: usize,
        vs: &[FE],
        y_stars: &[FE],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        let mut x_stars: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
        for item in x_stars.iter_mut() {
            *item = channel.read_fe()?;
        }
        let y = self
            .pows
            .iter()
            .zip(x_stars.into_iter().zip(y_stars.iter()))
            .map(|(pow, (x, y))| (*y - self.delta.multiply_by_prime_subfield(x)) * *pow)
            .sum();
        let mut vb = FE::ZERO;
        for v in vs.iter() {
            vb += *v * FE::random(&mut rng_chi);
        }
        vb -= y;
        let res = eq_receive(channel, rng, &vb)?;
        if res {
            Ok(())
        } else {
            Err(Error::EqCheckFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::base_svole::{Receiver as BaseReceiver, Sender as BaseSender},
        SpsReceiver, SpsSender,
    };
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_spsvole_<FE: FF>(cols: usize, weight: usize) {
        let n = cols / weight;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = super::super::utils::gen_pows();
            let mut base = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            let uw = base.send(&mut channel, weight, &mut rng).unwrap();
            let mut spsvole = SpsSender::<FE>::init(&mut channel, pows, &mut rng).unwrap();
            spsvole.send(&mut channel, n, &uw, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = super::super::utils::gen_pows();
        let mut base = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let v = base.receive(&mut channel, weight, &mut rng).unwrap();
        let mut spsvole =
            SpsReceiver::<FE>::init(&mut channel, pows.clone(), base.delta(), &mut rng).unwrap();
        let vs = spsvole.receive(&mut channel, n, &v, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..weight {
            for j in 0..n {
                let right =
                    base.delta().multiply_by_prime_subfield(uws[i * n + j].0) + vs[i * n + j];
                assert_eq!(uws[i * n + j].1, right);
            }
        }
    }

    #[test]
    fn test_spsvole() {
        let cols = 10_805_248;
        let weight = 1_319;

        test_spsvole_::<Fp>(cols, weight);
        test_spsvole_::<Gf128>(cols, weight);
        test_spsvole_::<F2>(cols, weight);
        test_spsvole_::<F61p>(cols, weight);
    }
}
