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
pub struct Sender<FE: FF> {
    copee: CopeeSender<FE>,
    pows: Vec<FE>,
}

/// sVOLE receiver.
pub struct Receiver<FE: FF> {
    copee: CopeeReceiver<FE>,
    pows: Vec<FE>,
}

pub type BaseSender<FE> = Sender<FE>;
pub type BaseReceiver<FE> = Receiver<FE>;

impl<FE: FF> Sender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        let copee = CopeeSender::<FE>::init(channel, rng)?;
        Ok(Self { copee, pows })
    }

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

impl<FE: FF> Receiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        let cp = CopeeReceiver::<FE>::init(channel, rng)?;
        Ok(Self { copee: cp, pows })
    }

    pub fn delta(&self) -> FE {
        self.copee.delta()
    }

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
            Err(Error::CorrelationCheckError(
                "Correlation check fails in base vole protocol, i.e, w != u'Δ + v".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BaseReceiver, BaseSender};
    use crate::svole::svole_ext::lpn_params::{LpnExtendParams, LpnSetupParams};
    use scuttlebutt::field::{F61p, FiniteField as FF, Fp, Gf128, F2};
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    fn test_base_svole<FE: FF>(len: usize) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = BaseSender::<FE>::init(&mut channel, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = BaseReceiver::<FE>::init(&mut channel, &mut rng).unwrap();
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
        let len = LpnSetupParams::ROWS;
        test_base_svole::<Fp>(len);
        test_base_svole::<Gf128>(len);
        test_base_svole::<F2>(len);
        test_base_svole::<F61p>(len);
    }

    #[test]
    fn test_base_svole_extend_params() {
        let len = LpnExtendParams::ROWS;
        test_base_svole::<Fp>(len);
        test_base_svole::<Gf128>(len);
        test_base_svole::<F2>(len);
        test_base_svole::<F61p>(len);
    }
}
