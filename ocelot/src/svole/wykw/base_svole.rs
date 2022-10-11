//! Implementation of the Weng-Yang-Katz-Wang Base sVOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use super::{
    copee::{CopeeReceiver, CopeeSender},
    utils::Powers,
};
use crate::errors::Error;
use crate::svole::wykw::specialization::FiniteFieldSpecialization;
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{field::FiniteField as FF, AbstractChannel, AesRng};
use std::marker::PhantomData;

pub(super) struct Sender<FE: FF, S: FiniteFieldSpecialization<FE>> {
    copee: CopeeSender<FE>,
    pows: Powers<FE>,
    phantom: PhantomData<S>,
}

pub struct Receiver<FE: FF> {
    copee: CopeeReceiver<FE>,
    pows: Powers<FE>,
}

impl<FE: FF, S: FiniteFieldSpecialization<FE>> Sender<FE, S> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let copee = CopeeSender::<FE>::init(channel, pows.clone(), rng)?;
        Ok(Self {
            copee,
            pows,
            phantom: PhantomData,
        })
    }

    pub fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        n: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<S::SenderPairContents>, Error> {
        let mut uws = Vec::with_capacity(n);
        for _ in 0..n {
            let u = FE::PrimeField::random(&mut rng);
            let w = self.copee.send(channel, &u)?;
            uws.push(S::new_sender_pair(u, w));
        }
        let mut z: FE = FE::ZERO;
        let mut x: FE = FE::ZERO;
        for pow in self.pows.get().iter() {
            let a = FE::PrimeField::random(&mut rng);
            let c = self.copee.send(channel, &a)?;
            z += c * *pow;
            x += pow.multiply_by_prime_subfield(a);
        }
        channel.flush()?;
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        for (u, w) in uws.iter().copied().map(S::extract_sender_pair) {
            let chi = FE::random(&mut rng_chi);
            z += chi * w;
            x += chi.multiply_by_prime_subfield(u);
        }
        channel.write_fe(&x)?;
        channel.write_fe(&z)?;
        Ok(uws)
    }
}

impl<FE: FF> Receiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        pows: Powers<FE>,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let cp = CopeeReceiver::<FE>::init(channel, pows.clone(), rng)?;
        Ok(Self { copee: cp, pows })
    }
    pub fn delta(&self) -> FE {
        self.copee.delta()
    }
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
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
    use super::{super::utils::Powers, Receiver, Sender};
    use crate::svole::wykw::specialization::{FiniteFieldSpecialization, NoSpecialization};
    use scuttlebutt::{
        field::{F128b, F40b, F61p, FiniteField as FF},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_base_svole<FE: FF, S: FiniteFieldSpecialization<FE>>(len: usize) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let pows = <Powers<_> as Default>::default();
            let mut vole = Sender::<FE, S>::init(&mut channel, pows, &mut rng).unwrap();
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
            let mut right = delta.multiply_by_prime_subfield(S::extract_sender_pair(uw_s[i]).0);
            right += vs[i];
            assert_eq!(S::extract_sender_pair(uw_s[i]).1, right);
        }
    }

    fn test_base_vole_setup_params_all_fields(len: usize) {
        test_base_svole::<F128b, NoSpecialization>(len);
        test_base_svole::<F61p, NoSpecialization>(len);
        test_base_svole::<F40b, NoSpecialization>(len);
    }

    #[test]
    fn test_base_svole_setup_params() {
        let len = 19870; //LpnSetupParams::ROWS;
        test_base_vole_setup_params_all_fields(len)
    }
}
