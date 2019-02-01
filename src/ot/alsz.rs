use super::Stream;
use crate::hash_aes::AesHash;
use crate::rand_aes::AesRng;
use crate::utils;
use crate::ObliviousTransfer;
use arrayref::array_ref;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

/// Implementation of the Asharov-Lindell-Schneider-Zohner semi-honest secure
/// oblivious transfer extension protocol (cf.
/// <https://eprint.iacr.org/2016/602>, Protocol 4).
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
        let hash = AesHash::new(&[0u8; 16]); // XXX IV should be chosen at random
        let s = (0..nrows)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let s_ = utils::boolvec_to_u8vec(&s);
        let ks = self.ot.receive(&s, SEED_LENGTH)?;
        let rngs = ks
            .into_iter()
            .map(|k| AesRng::new(*array_ref![k, 0, SEED_LENGTH]));
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, rng)) in s.into_iter().zip(rngs).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            self.stream.read_bytes_inplace(&mut u)?;
            let u = if b { u.clone() } else { vec![0u8; ncols / 8] };
            rng.random(&mut q);
            utils::xor_inplace(&mut q, &u);
        }
        let mut qs = utils::transpose(&qs, nrows, ncols);
        for (j, input) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            let y0 = utils::xor(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.0);
            utils::xor_inplace(&mut q, &s_);
            let y1 = utils::xor(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.1);
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
        let hash = AesHash::new(&[0u8; 16]); // XXX IV should be chosen at random
        let ks = (0..nrows)
            .map(|_| {
                (
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                    self.rng.gen::<[u8; SEED_LENGTH]>().to_vec(),
                )
            })
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(&ks, SEED_LENGTH)?;
        let rngs = ks.into_iter().map(|(k0, k1)| {
            (
                AesRng::new(*array_ref![k0, 0, SEED_LENGTH]),
                AesRng::new(*array_ref![k1, 0, SEED_LENGTH]),
            )
        });
        let r = utils::boolvec_to_u8vec(inputs);
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for (j, (rng0, rng1)) in rngs.enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t = &mut ts[range];
            rng0.random(&mut t);
            rng1.random(&mut g);
            utils::xor_inplace(&mut g, &t);
            utils::xor_inplace(&mut g, &r);
            self.stream.write_bytes(&g)?;
        }
        let ts = utils::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(ncols);
        let mut y0 = vec![0u8; 16];
        let mut y1 = vec![0u8; 16];
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = &ts[range];
            self.stream.read_bytes_inplace(&mut y0)?;
            self.stream.read_bytes_inplace(&mut y1)?;
            let mut y = if *b { y1.clone() } else { y0.clone() };
            utils::xor_inplace(&mut y, &hash.cr_hash(j, array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
    use itertools::izip;
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
        for (b, result, m0, m1) in izip!(bs_, results, m0s_, m1s_) {
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
