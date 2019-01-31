use super::Stream;
use crate::rand_aes::AesRng;
use crate::ObliviousTransfer;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct AlszOT<S: Read + Write + Send, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

const SEED_LENGTH: usize = 16;

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
        let (nrows, ncols) = (128, m);
        let cipher = super::cipher(&[0u8; 16]); // XXX IV should be chosen at random
        let s = (0..nrows)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let s_ = super::boolvec_to_u8vec(&s);
        let ks = self.ot.receive(&s, SEED_LENGTH)?;
        let mut qs = vec![0u8; nrows * ncols / 8];
        for (j, (b, k)) in s.into_iter().zip(ks.into_iter()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let u = self.stream.read_bytes(ncols / 8)?;
            let u = if b { u } else { vec![0u8; ncols / 8] };
            let rng = AesRng::new(*array_ref![k, 0, SEED_LENGTH]);
            let g = rng.random(ncols / 8);
            qs[range].clone_from_slice(&super::xor(&u, &g));
        }
        let qs = super::transpose(&qs, nrows, ncols);
        for j in 0..ncols {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let q = qs.get(range).unwrap();
            let y0 = super::xor(&super::hash(j, &q, &cipher), &inputs[j].0);
            let y1 = super::xor(&super::hash(j, &super::xor(&q, &s_), &cipher), &inputs[j].1);
            self.stream.write_bytes(&y0)?;
            self.stream.write_bytes(&y1)?;
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
        let (nrows, ncols) = (128, m);
        let cipher = super::cipher(&[0u8; 16]); // XXX IV should be chosen at random
        let ks = (0..nrows)
            .map(|_| {
                (
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                )
            })
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(&ks, SEED_LENGTH)?;
        let r = super::boolvec_to_u8vec(inputs);
        let mut ts = vec![0u8; nrows * ncols / 8];
        for (j, (k0, k1)) in ks.into_iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let rng = AesRng::new(*array_ref![k0, 0, SEED_LENGTH]);
            let t = rng.random(ncols / 8);
            let rng = AesRng::new(*array_ref![k1, 0, SEED_LENGTH]);
            let g = rng.random(ncols / 8);
            let u = super::xor(&t, &g);
            let u = super::xor(&u, &r);
            self.stream.write_bytes(&u)?;
            ts[range].clone_from_slice(&t);
        }
        let ts = super::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(ncols);
        for (j, b) in inputs.into_iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = ts.get(range).unwrap();
            let y0 = self.stream.read_bytes(16)?;
            let y1 = self.stream.read_bytes(16)?;
            let y = if *b { y1 } else { y0 };
            let r = super::xor(&y, &super::hash(j, &t, &cipher));
            out.push(r);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const T: usize = 1 << 12;

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
    fn test() {
        test_ot::<DummyOT<UnixStream>>(T);
    }
}
