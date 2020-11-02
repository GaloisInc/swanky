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
        uws: &(FE::PrimeField, FE),
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let depth = 128 - (n as u128 - 1).leading_zeros() as usize;
        let (a, delta) = *uws;
        let mut beta = FE::PrimeField::random(&mut rng);
        while beta == FE::PrimeField::ZERO {
            beta = FE::PrimeField::random(&mut rng);
        }
        let a_prime = beta - a;
        channel.write_fe(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut uws = vec![(FE::PrimeField::ZERO, FE::ZERO); n];
        uws[alpha].0 = beta;
        let mut choices = unpack_bits(&(!alpha).to_le_bytes(), depth);
        choices.reverse(); // to get the first bit as MSB.
        let keys = self.ot.receive(channel, &choices, rng)?;
        let d: FE = channel.read_fe()?;
        let vs: Vec<FE> = ggm_prime::<FE>(alpha, &keys);
        for i in 0..n {
            if i != alpha {
                uws[i].1 = vs[i];
            }
        }
        let sum = uws.iter().map(|(_, w)| *w).sum();
        uws[alpha].1 = delta - (d + sum);
        Ok(uws)
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
        len: usize,
        v: &FE,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let depth = 128 - (len as u128 - 1).leading_zeros();
        let b = *v;
        let a_prime = channel.read_fe::<FE::PrimeField>()?;
        let gamma = b - self.delta.multiply_by_prime_subfield(a_prime);
        let seed = rng.gen::<Block>();
        let (vs, keys) = ggm::<FE>(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        let d = gamma - vs.clone().into_iter().sum();
        channel.write_fe(d)?;
        channel.flush()?;
        Ok(vs)
    }
    /// Batch consistency check that can be called after bunch of iterations.
    pub fn receive_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        vs: Vec<Vec<FE>>,
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

    fn test_spsvole<FE: FF>(len: usize) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = crate::svole::utils::gen_pows();
            let mut base = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            let uw = base.send(&mut channel, 1, &mut rng).unwrap();
            let mut vole = SpsSender::<FE>::init(&mut channel, pows, 1, &mut rng).unwrap();
            vole.send(&mut channel, len, &uw[0], &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = crate::svole::utils::gen_pows();
        let mut base = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let v = base.receive(&mut channel, 1, &mut rng).unwrap();
        let mut vole =
            SpsReceiver::<FE>::init(&mut channel, pows.clone(), base.delta(), 1, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, len, &v[0], &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..len as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    #[test]
    fn test_sp_svole() {
        for i in 1..14 {
            let leaves = 1 << i;
            test_spsvole::<Fp>(leaves);
            test_spsvole::<Gf128>(leaves);
            test_spsvole::<F2>(leaves);
            test_spsvole::<F61p>(leaves);
        }
    }
}
