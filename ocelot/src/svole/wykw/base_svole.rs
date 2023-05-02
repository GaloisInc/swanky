//! Implementation of the Weng-Yang-Katz-Wang Base sVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use super::{
    copee::{CopeeReceiver, CopeeSender},
    utils::Powers,
};
use crate::errors::Error;
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{
    field::{Degree, FiniteField as FF},
    ring::FiniteRing,
    AbstractChannel, AesRng,
};

/// The base VOLE sender
pub struct Sender<FE: FF> {
    copee: CopeeSender<FE>,
    pows: Powers<FE>,
}

/// The base VOLE receiver
pub struct Receiver<FE: FF> {
    copee: CopeeReceiver<FE>,
    pows: Powers<FE>,
}

impl<FE: FF> Sender<FE> {
    /// Initalize the base vole sender
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let copee = CopeeSender::<FE>::init(channel, pows.clone(), rng)?;
        Ok(Self { copee, pows })
    }

    /// Recieve `n` `(x, beta)` pairs such that $`T = \beta - x \cdot \Delta`$
    pub fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        n: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let mut uws = Vec::with_capacity(n);
        for _ in 0..n {
            let u = FE::PrimeField::random(&mut rng);
            let w = self.copee.send(channel, &u)?;
            uws.push((u, w));
        }
        let mut z: FE = FE::ZERO;
        let mut x: FE = FE::ZERO;
        for pow in self.pows.get().iter() {
            let a = FE::PrimeField::random(&mut rng);
            let c = self.copee.send(channel, &a)?;
            z += c * *pow;
            x += a * *pow;
        }
        channel.flush()?;
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        for (u, w) in uws.iter().copied() {
            let chi = FE::random(&mut rng_chi);
            z += chi * w;
            x += u * chi;
        }
        channel.write_serializable(&x)?;
        channel.write_serializable(&z)?;
        Ok(uws)
    }
}

impl<FE: FF> Receiver<FE> {
    /// Initalize the base vole receiver with a random `delta`
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let cp = CopeeReceiver::<FE>::init(channel, pows.clone(), rng)?;
        Ok(Self { copee: cp, pows })
    }
    /// Initalize the base vole receiver with a supplied `delta`
    pub fn init_with_picked_delta<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
        delta: FE,
    ) -> Result<Self, Error> {
        let cp = CopeeReceiver::<FE>::init_with_picked_delta(channel, pows.clone(), rng, delta)?;
        Ok(Self { copee: cp, pows })
    }
    /// Return the `delta` associated with this receiver
    pub fn delta(&self) -> FE {
        self.copee.delta()
    }
    /// Recieve `len` base VOLE `T` values where $`T = \beta - x \cdot \Delta`$
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = Degree::<FE>::USIZE;
        let mut v: Vec<FE> = vec![FE::ZERO; len];
        let seed = rng.gen();
        let mut rng_chi = AesRng::from_seed(seed);
        let mut y: FE = FE::ZERO;
        for i in 0..len {
            v[i] = self.copee.receive(channel)?;
        }
        y += v.iter().map(|v_i| FE::random(&mut rng_chi) * *v_i).sum();

        for i in 0..r {
            let b = self.copee.receive(channel)?;
            y += self.pows.get()[i] * b
        }
        channel.write_block(&seed)?;
        channel.flush()?;
        let x = channel.read_serializable()?;
        let z: FE = channel.read_serializable()?;
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
    use super::{super::utils::Powers, Receiver, Sender};
    use scuttlebutt::{
        field::{F128b, F40b, F61p, FiniteField as FF},
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
            let pows = <Powers<_> as Default>::default();
            let mut vole = Sender::<FE>::init(&mut channel, pows, &mut rng).unwrap();
            vole.send(&mut channel, len, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let pows = <Powers<_> as Default>::default();
        let mut vole = Receiver::<FE>::init(&mut channel, pows, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, len, &mut rng).unwrap();
        let delta = vole.delta();
        let uw_s = handle.join().unwrap();
        for i in 0..len {
            let mut right = uw_s[i].0 * delta;
            right += vs[i];
            assert_eq!(uw_s[i].1, right);
        }
    }

    fn test_base_vole_setup_params_all_fields(len: usize) {
        test_base_svole::<F128b>(len);
        test_base_svole::<F61p>(len);
        test_base_svole::<F40b>(len);
    }

    #[test]
    fn test_base_svole_setup_params() {
        let len = 19870; //LpnSetupParams::ROWS;
        test_base_vole_setup_params_all_fields(len)
    }
}
