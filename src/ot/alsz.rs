use super::Stream;
use crate::ot::ObliviousTransfer;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct AlszOT<S: Read + Write + Send, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

type Prng = ChaChaRng;
const SEED_LENGTH: usize = 32;

impl<S: Read + Write + Send, OT: ObliviousTransfer<S>> ObliviousTransfer<S> for AlszOT<S, OT> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let ot = OT::new(stream.clone());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error> {
        if nbytes != 16 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "ALSZ OT only supports 128-bit inputs",
            )));
        }
        let m = inputs.len();
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        if m <= 128 {
            // Just do normal OT
            return self.ot.send(inputs, nbytes);
        }
        let cipher = super::cipher(&[0u8; 16]);
        let s = (0..128)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let s_ = super::boolvec_to_u128(&s);
        let ks = self.ot.receive(&s, SEED_LENGTH)?;
        let mut qs = Vec::with_capacity(128);
        for (b, k) in s.into_iter().zip(ks.into_iter()) {
            let u = self.stream.read_bytes(m / 8)?;
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k, 0, SEED_LENGTH]);
            let g = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let u = if b { u } else { vec![0u8; m / 8] };
            qs.push(super::xor(&u, &g));
        }
        let qs_ = super::transpose(&qs, m);
        for (j, q) in qs_.into_iter().enumerate() {
            let q = super::u8vec_to_u128(&q);
            let y0 = super::hash(j, &q, &cipher) ^ super::u8vec_to_u128(&inputs[j].0);
            let y1 = super::hash(j, &(q ^ s_), &cipher) ^ super::u8vec_to_u128(&inputs[j].1);
            self.stream.write_u128(&y0)?;
            self.stream.write_u128(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        if nbytes != 16 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "ALSZ OT only supports 128-bit inputs",
            )));
        }
        let m = inputs.len();
        if m <= 128 {
            // Just do normal OT
            return self.ot.receive(inputs, nbytes);
        }
        let cipher = super::cipher(&[0u8; 16]);
        let r = inputs.iter().cloned().collect::<super::BV>();
        let ks = (0..128)
            .map(|_| {
                (
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                )
            })
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(&ks, SEED_LENGTH)?;
        let mut ts = Vec::with_capacity(128);
        let r_: Vec<u8> = r.clone().into();
        for (k0, k1) in ks.into_iter() {
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k0, 0, SEED_LENGTH]);
            let t = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let mut rng: Prng = SeedableRng::from_seed(*array_ref![k1, 0, SEED_LENGTH]);
            let g = (0..m / 8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let u = super::xor(&t, &g);
            let u = super::xor(&u, &r_);
            self.stream.write_bytes(&u)?;
            ts.push(t);
        }
        let ts_ = super::transpose(&ts, m);
        let mut out = Vec::with_capacity(m);
        for ((j, b), t) in r.into_iter().enumerate().zip(ts_) {
            let t = super::u8vec_to_u128(&t);
            let y0 = self.stream.read_u128()?;
            let y1 = self.stream.read_u128()?;
            let y = if b { y1 } else { y0 };
            let r = y ^ super::hash(j, &t, &cipher);
            out.push(r.to_le_bytes().to_vec());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::ChouOrlandiOT;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const T: usize = 1 << 8;

    fn rand_u128_vec(size: usize) -> Vec<u128> {
        (0..size).map(|_| rand::random::<u128>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OT: ObliviousTransfer<UnixStream>>(t: usize) {
        let m0s = rand_u128_vec(t);
        let m1s = rand_u128_vec(t);
        let bs = rand_bool_vec(t);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => panic!("Couldn't create pair of sockets: {:?}", e),
        };
        let handle = std::thread::spawn(move || {
            let mut otext = AlszOT::<UnixStream, OT>::new(sender.clone());
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .map(|(a, b)| (a.to_le_bytes().to_vec(), b.to_le_bytes().to_vec()))
                .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
            otext.send(&ms, 16).unwrap();
        });
        let mut otext = AlszOT::<UnixStream, OT>::new(receiver.clone());
        let results = otext.receive(&bs, 16).unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(
                u128::from_ne_bytes(*array_ref![result, 0, 16]),
                if b { m1 } else { m0 }
            )
        }
        handle.join().unwrap();
    }

    #[test]
    fn test_chou_orlandi() {
        test_ot::<ChouOrlandiOT<UnixStream>>(T);
    }
}
