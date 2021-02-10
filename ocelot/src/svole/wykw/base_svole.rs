// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang Base SVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use super::copee::{CopeeReceiver, CopeeSender};
use crate::errors::Error;
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel};

/// sVOLE sender.
pub struct Sender<'a, FE: FF> {
    copee: CopeeSender<'a, FE>,
    pows: &'a [FE],
}

/// sVOLE receiver.
pub struct Receiver<'a, FE: FF> {
    copee: CopeeReceiver<'a, FE>,
    pows: &'a [FE],
}

impl<'a, FE: FF> Sender<'a, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: &'a [FE],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let copee = CopeeSender::<FE>::init(channel, pows, rng)?;
        Ok(Self { copee, pows })
    }

    /// Runs SVOLE extend on input length `len` and returns `(u, w)`, where `u`
    /// is a randomly generated input vector of length `len` from
    /// `FE::PrimeField` such that the correlation `w = u'Δ + v`, `u'` is the
    /// converted vector of `u` to the vector of type `FE`, holds. The vector
    /// length `len` should match with the Receiver's input length, otherwise,
    /// the program runs forever.
    pub fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let mut uws: Vec<(FE::PrimeField, FE)> = (0..len)
            .map(|_| (FE::PrimeField::random(&mut rng), FE::ZERO))
            .collect();
        let mut z: FE = FE::ZERO;
        let mut x: FE = FE::ZERO;
        for i in 0..len {
            uws[i].1 = self.copee.send(channel, &uws[i].0)?;
        }
        for pow in self.pows.iter() {
            let a = FE::PrimeField::random(&mut rng);
            let c = self.copee.send(channel, &a)?;
            z += c * *pow;
            x += pow.multiply_by_prime_subfield(a);
        }
        channel.flush()?;

        for i in 0..len {
            let chi = channel.read_fe::<FE>()?;
            z += chi * uws[i].1;
            x += chi.multiply_by_prime_subfield(uws[i].0);
        }
        channel.write_fe(x)?;
        channel.write_fe(z)?;
        Ok(uws)
    }
}

impl<'a, FE: FF> Receiver<'a, FE> {
    /// Runs any one-time initialization.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        pows: &'a [FE],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let cp = CopeeReceiver::<FE>::init(channel, pows, rng)?;
        Ok(Self { copee: cp, pows })
    }
    /// Returns the receiver choice `Δ`.
    pub fn delta(&self) -> FE {
        self.copee.delta()
    }
    /// Runs SVOLE extend on input length `len` and returns a vector `v` such
    /// that the correlation `w = u'Δ + v` holds. Note that `u'` is the
    /// converted vector from `u` to the vector of elements of the extended
    /// field `FE`. The vector length `len` should match with the Sender's input
    /// `len`, otherwise it never terminates.
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut v: Vec<FE> = vec![FE::ZERO; len];
        let chi: Vec<FE> = (0..len).map(|_| FE::random(&mut rng)).collect();
        let mut y: FE = FE::ZERO;
        for i in 0..len {
            v[i] = self.copee.receive(channel)?;
            y += chi[i] * v[i];
        }
        for i in 0..r {
            let b = self.copee.receive(channel)?;
            y += self.pows[i] * b
        }
        for x in chi.iter() {
            channel.write_fe(*x)?;
        }
        channel.flush()?;
        let x = channel.read_fe()?;
        let z: FE = channel.read_fe()?;
        let mut delta = self.copee.delta();
        delta *= x;
        delta += y;
        if z == delta {
            Ok(v)
        } else {
            Err(Error::CorrelationCheckFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Receiver, Sender};
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_base_svole<FE: FF>(len: usize) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = super::super::utils::gen_pows();
            let mut vole = Sender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = super::super::utils::gen_pows();
        let mut vole = Receiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, len, &mut rng).unwrap();
        let delta = vole.delta();
        let uw_s = handle.join().unwrap();
        for i in 0..len {
            let mut right = delta.multiply_by_prime_subfield(uw_s[i].0);
            right += vs[i];
            assert_eq!(uw_s[i].1, right);
        }
    }

    #[test]
    fn test_base_svole_setup_params() {
        let len = 19870; //LpnSetupParams::ROWS;
        test_base_svole::<Fp>(len);
        test_base_svole::<Gf128>(len);
        test_base_svole::<F2>(len);
        test_base_svole::<F61p>(len);
    }

    #[test]
    fn test_base_svole_extend_params() {
        let len = 589_760; //LpnExtendParams::ROWS;
        test_base_svole::<Fp>(len);
        test_base_svole::<Gf128>(len);
        test_base_svole::<F2>(len);
        test_base_svole::<F61p>(len);
    }
}
