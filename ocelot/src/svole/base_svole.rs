// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang base SVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 13).

use crate::{
    errors::Error,
    svole::copee::{CopeeReceiver, CopeeSender},
};
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

/// Base svole sender.
pub type BaseSender<'a, FE> = Sender<'a, FE>;
/// Base svole receiver.
pub type BaseReceiver<'a, FE> = Receiver<'a, FE>;

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
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let u: Vec<FE::PrimeField> = (0..len).map(|_| FE::PrimeField::random(&mut rng)).collect();
        let a: Vec<FE::PrimeField> = (0..r).map(|_| FE::PrimeField::random(&mut rng)).collect();
        let mut w = vec![FE::ZERO; len];
        for i in 0..len {
            w[i] = self.copee.send(channel, &u[i])?;
        }
        let mut z: FE = FE::ZERO;
        for (i, x) in a.iter().enumerate().take(r) {
            let c = self.copee.send(channel, x)?;
            z += c * self.pows[i];
        }
        channel.flush()?;
        let mut x: FE = FE::ZERO;
        for i in 0..len {
            let chi = channel.read_fe::<FE>()?;
            z += chi * w[i];
            x += chi.multiply_by_prime_subfield(u[i]);
        }
        x += a
            .iter()
            .zip(self.pows.iter())
            .map(|(&a, &pow)| pow.multiply_by_prime_subfield(a))
            .sum();
        channel.write_fe(x)?;
        channel.write_fe(z)?;
        let res = u.iter().zip(w.iter()).map(|(u, w)| (*u, *w)).collect();
        Ok(res)
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
    use super::{BaseReceiver, BaseSender};
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
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
            let pows = crate::svole::utils::gen_pows();
            let mut vole = BaseSender::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = crate::svole::utils::gen_pows();
        let mut vole = BaseReceiver::<FE>::init(&mut channel, &pows, &mut rng).unwrap();
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
