// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of single-point svole protocol.

use crate::{
    errors::Error,
    ot::{KosReceiver, KosSender, Receiver as OtReceiver, Sender as OtSender},
    svole::svole_ext::ggm_utils::{
        dot_product, ggm, ggm_prime, point_wise_addition, scalar_multiplication,
    },
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
    weight: usize,
}

/// SpsVole Receiver.
pub struct Receiver<OT: OtSender, FE: FF> {
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
    weight: usize,
}
/// Alias for SpsVole Sender.
pub type SpsSender<FE> = Sender<KosReceiver, FE>;
/// Alias for SpsVole Receiver.
pub type SpsReceiver<FE> = Receiver<KosSender, FE>;

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
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, rng)?;
        Ok(Self { pows, ot, weight })
    }
    /// Runs single-point svole and outputs pair of vectors `(u, w)` such that
    /// the correlation `w = u'Δ + v` holds. Note that `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. For simplicity, the vector
    /// length `n` assumed to be power of `2` as it represents the number of leaves in the GGM tree
    /// and should match with the receiver input length.
    pub fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        n: usize,
        uws: &[(FE::PrimeField, FE)],
        mut rng: &mut RNG,
    ) -> Result<Vec<Vec<(FE::PrimeField, FE)>>, Error> {
        let depth = 128 - (n as u128 - 1).leading_zeros() as usize;
        let len = uws.len();
        let mut result = vec![vec![(FE::PrimeField::ZERO, FE::ZERO); n]; len];
        let mut betas = Vec::with_capacity(len);
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
        let mut tmps = Vec::with_capacity(len);
        for (i, beta) in betas.into_iter().enumerate() {
            let alpha = rng.gen_range(0, n);
            result[i][alpha].0 = beta;
            let mut choices_ = unpack_bits(&(!alpha).to_le_bytes(), depth);
            choices_.reverse(); // to get the first bit as MSB.
            let keys = self.ot.receive(channel, &choices_, rng)?;
            let vs: Vec<FE> = ggm_prime(alpha, &keys);
            for j in 0..n {
                if j != alpha {
                    result[i][j].1 = vs[j];
                }
            }
            let sum = vs.iter().map(|v| *v).sum();
            tmps.push((alpha, sum));
        }
        for (i, ((_, delta), (alpha, sum))) in uws.iter().zip(tmps.into_iter()).enumerate() {
            let d: FE = channel.read_fe()?;
            result[i][alpha].1 = *delta - (d + sum);
        }
        Ok(result)
    }
    /// Batch consistency check that can be called after bunch of iterations.
    pub fn send_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        uws: &[Vec<(FE::PrimeField, FE)>],
        buws: &[(FE::PrimeField, FE)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let xzs = &buws;
        let n = len;
        let t = self.weight;
        // Generate `chis` from seed and send seed to receiver.
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        let mut rng_chi = AesRng::from_seed(seed);
        let chis: Vec<FE> = (0..n * t).map(|_| FE::random(&mut rng_chi)).collect();
        let mut chi_alphas = Vec::with_capacity(r * t);
        for j in 0..t {
            for (i, (u, _)) in uws[j].iter().enumerate() {
                // There will be one, and exactly one, `u` (= `β`) which is
                // non-zero. Don't `break` after we hit this one to avoid a
                // potential side-channel attack.
                if *u != FE::PrimeField::ZERO {
                    chi_alphas.extend(scalar_multiplication(
                        *u,
                        &chis[n * j + i].to_polynomial_coefficients(),
                    ));
                }
            }
        }
        let mut x_stars = vec![FE::PrimeField::ZERO; r];
        for i in 0..t {
            x_stars = point_wise_addition(x_stars.iter(), chi_alphas[i * r..(i + 1) * r].iter());
        }
        for (x_star, (x, _)) in x_stars.iter().zip(xzs.iter()) {
            channel.write_fe(*x_star - *x)?;
        }
        let z = dot_product(xzs.iter().map(|(_, z)| z), self.pows.iter());
        let va = (0..t)
            .map(|j| {
                dot_product(
                    chis[n * j..n * (j + 1)].iter(),
                    uws[j].iter().map(|(_, w)| w),
                )
            })
            .sum::<FE>()
            - z;
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
        weight: usize,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, &mut rng)?;
        Ok(Self {
            pows,
            delta,
            ot,
            weight,
        })
    }
    /// Returns the receiver choices during the OT call.
    pub fn delta(&self) -> FE {
        self.delta
    }
    /// Runs single-point svole and outputs a vector `v` such that
    /// the correlation `w = u'Δ + v` holds. Again, `u'` is the converted vector from
    /// `u` to the vector of elements of the extended field `FE`. Of course, the vector
    /// length `len` is suppose to be in multiples of `2` as it represents the number of
    /// leaves in the GGM tree and should match with the sender input length.
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        nleaves: usize,
        vs: &[FE],
        rng: &mut RNG,
    ) -> Result<Vec<Vec<FE>>, Error> {
        let depth = 128 - (nleaves as u128 - 1).leading_zeros() as usize;
        let len = vs.len();
        let mut gammas = Vec::with_capacity(len);
        let mut ds = Vec::with_capacity(len);
        let mut result = vec![];
        for (_, b) in vs.iter().enumerate() {
            let a_prime = channel.read_fe::<FE::PrimeField>()?;
            let gamma = *b - self.delta.multiply_by_prime_subfield(a_prime);
            gammas.push(gamma);
        }
        for gamma in gammas.into_iter() {
            let (vs_, keys_) = ggm(depth as usize, rng);
            // XXX hmm I would have thought batching OTs would make things more
            // efficient, but that doesn't seem to be the case. Probably needs
            // further investigation.
            self.ot.send(channel, &keys_, rng)?;
            let d = gamma - vs_.iter().map(|v| *v).sum();
            ds.push(d);
            result.push(vs_);
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
        len: usize,
        vs: &[Vec<FE>],
        bvs: &[FE],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let y_stars = &bvs;
        let n = len;
        let t = self.weight;
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        let chis: Vec<FE> = (0..t * n).map(|_| FE::random(&mut rng_chi)).collect();
        let mut x_stars: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
        for item in x_stars.iter_mut() {
            *item = channel.read_fe()?;
        }
        let ys: Vec<FE> = y_stars
            .iter()
            .zip(x_stars.into_iter())
            .map(|(y, x)| *y - self.delta.multiply_by_prime_subfield(x))
            .collect();
        let y = dot_product(ys.iter(), self.pows.iter());
        let vb = (0..t)
            .map(|j| dot_product(chis[n * j..n * (j + 1)].iter(), vs[j].iter()))
            .sum::<FE>()
            - y;
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
    use crate::svole::{
        base_svole::{BaseReceiver, BaseSender},
        svole_ext::sp_svole::{SpsReceiver, SpsSender},
    };
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_spsvole<FE: FF>(len: usize, nleaves: usize) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = crate::svole::utils::gen_pows();
            let mut base = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            let uw = base.send(&mut channel, len, &mut rng).unwrap();
            let mut spsvole = SpsSender::<FE>::init(&mut channel, pows, len, &mut rng).unwrap();
            spsvole.send(&mut channel, nleaves, &uw, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = crate::svole::utils::gen_pows();
        let mut base = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let v = base.receive(&mut channel, len, &mut rng).unwrap();
        let mut spsvole =
            SpsReceiver::<FE>::init(&mut channel, pows.clone(), base.delta(), len, &mut rng)
                .unwrap();
        let vs = spsvole
            .receive(&mut channel, nleaves, &v, &mut rng)
            .unwrap();
        let uws = handle.join().unwrap();
        for i in 0..len {
            for j in 0..nleaves {
                let right = spsvole.delta().multiply_by_prime_subfield(uws[i][j].0) + vs[i][j];
                assert_eq!(uws[i][j].1, right);
            }
        }
    }

    #[test]
    fn test_sp_svole() {
        let len = 1;
        for i in 1..14 {
            let nleaves = 1 << i;
            test_spsvole::<Fp>(len, nleaves);
            test_spsvole::<Gf128>(len, nleaves);
            test_spsvole::<F2>(len, nleaves);
            test_spsvole::<F61p>(len, nleaves);
        }
    }
}
