use super::Stream;
use crate::ot::ObliviousTransfer;
use bitvec::BitVec;
use failure::Error;
use rand::rngs::{StdRng, ThreadRng};
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct AlszOT<S: Read + Write, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

type Prng = StdRng;
const SEED_LENGTH: usize = 32;

impl<S: Read + Write, OT: ObliviousTransfer<S>> ObliviousTransfer<S> for AlszOT<S, OT> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let ot = OT::new(stream.clone());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
        let ℓ = 128;
        let m = inputs.len();
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        if m <= ℓ {
            // Just do normal OT
            return self.ot.send(inputs);
        }
        let s = (0..ℓ)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let ks = self.ot.receive(&s, SEED_LENGTH)?;
        let mut qs = Vec::with_capacity(ℓ);
        for (s, k) in s.iter().zip(ks.iter()) {
            let u = self.stream.read_bytes(m / 8)?;
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k, 0, SEED_LENGTH]);
            let g = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let u = if *s { u } else { vec![0u8; m / 8] };
            qs.push(super::xor(&u, &g));
        }
        let qs_ = super::transpose(&qs, ℓ);
        for (j, q) in qs_.into_iter().enumerate() {
            let x0 = array_ref![inputs[j].0, 0, 16];
            let y0 = u128::from_ne_bytes(*x0) ^ hash(j, &q);
            let x1 = array_ref![inputs[j].1, 0, 16];
            let y1 = u128::from_ne_bytes(*x1) ^ hash(j, &(q ^ s.clone()));
            self.stream.write_u128(&y0)?;
            self.stream.write_u128(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        if nbytes != 16 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Currently only supports 128-bit inputs",
            )));
        }
        let ℓ = 128;
        let m = inputs.len();
        if m <= ℓ {
            // Just do normal OT
            return self.ot.receive(inputs, nbytes);
        }
        let r = inputs.iter().cloned().collect::<BitVec>();
        let ks = (0..ℓ)
            .map(|_| {
                (
                    rand::random::<[u8; SEED_LENGTH]>().to_vec(),
                    rand::random::<[u8; SEED_LENGTH]>().to_vec(),
                )
            })
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(&ks)?;
        let mut ts = Vec::with_capacity(ℓ);
        for (k0, k1) in ks.iter() {
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k0, 0, SEED_LENGTH]);
            let t = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k1, 0, SEED_LENGTH]);
            let g = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let u = super::xor(&t, &g);
            let r: Vec<u8> = r.clone().into();
            let u = super::xor(&u, &r);
            self.stream.write_bytes(&u)?;
            ts.push(t);
        }
        let ts_ = super::transpose(&ts, ℓ);
        let mut out = Vec::with_capacity(m);
        for ((j, b), t) in r.iter().enumerate().zip(ts_) {
            let y0 = self.stream.read_u128()?;
            let y1 = self.stream.read_u128()?;
            let y = if b { y1 } else { y0 };
            let r = y ^ hash(j, &BitVec::from(t));
            out.push(r.to_ne_bytes().to_vec());
        }
        Ok(out)
    }
}

fn hash(idx: usize, q: &BitVec) -> u128 {
    let mut h = Sha256::new();
    h.input(idx.to_ne_bytes());
    h.input(q);
    let result = h.result();
    let result = array_ref![result, 0, 16];
    u128::from_ne_bytes(result.clone())
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::ot::chou_orlandi::ChouOrlandiOT;
    use crate::ot::dummy::DummyOT;
    use crate::ot::naor_pinkas::NaorPinkasOT;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const N: usize = 256;

    fn rand_u128_vec(size: usize) -> Vec<u128> {
        (0..size).map(|_| rand::random::<u128>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OT: ObliviousTransfer<UnixStream>>(n: usize) {
        let m0s = rand_u128_vec(n);
        let m1s = rand_u128_vec(n);
        let bs = rand_bool_vec(n);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            let mut otext = AlszOT::<UnixStream, OT>::new(sender.clone());
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .map(|(a, b)| (a.to_ne_bytes().to_vec(), b.to_ne_bytes().to_vec()))
                .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
            otext.send(&ms).unwrap();
        });
        let mut otext = AlszOT::<UnixStream, OT>::new(receiver.clone());
        let results = otext.receive(&bs, 16).unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(
                u128::from_ne_bytes(*array_ref![result, 0, 16]),
                if b { m1 } else { m0 }
            )
        }
    }

    #[test]
    fn test_dummy() {
        test_ot::<DummyOT<UnixStream>>(N);
    }
    #[test]
    fn test_naor_pinkas() {
        test_ot::<NaorPinkasOT<UnixStream>>(N);
    }
    #[test]
    fn test_chou_orlandi() {
        test_ot::<ChouOrlandiOT<UnixStream>>(N);
    }
}
