use super::{ObliviousTransfer, Stream};
use crate::util;
use bitvec::BitVec;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct ChouOrlandiOT<T: Read + Write> {
    stream: Stream<T>,
    rng: ThreadRng,
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;
const KEYSIZE: usize = 16;

impl<T: Read + Write> ObliviousTransfer<T> for ChouOrlandiOT<T> {
    fn new(stream: Arc<Mutex<T>>) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, inputs: &[(BitVec, BitVec)]) -> Result<(), Error> {
        let y = Scalar::random(&mut self.rng);
        let s = P * y;
        self.stream.write_pt(&s)?;
        for input in inputs.iter() {
            let r = self.stream.read_pt()?;
            let k0 = super::hash_pt(&(r * y), KEYSIZE);
            let k1 = super::hash_pt(&((r - s) * y), KEYSIZE);
            let c0 = super::encrypt(&k0, &mut util::bitvec_to_vec(&input.0));
            let c1 = super::encrypt(&k1, &mut util::bitvec_to_vec(&input.1));
            self.stream.write_bytes(&c0)?;
            self.stream.write_bytes(&c1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[u16], nbits: usize) -> Result<Vec<BitVec>, Error> {
        let nbytes = nbits / 8;
        let mut outputs = Vec::with_capacity(inputs.len());
        let s = self.stream.read_pt()?;
        for input in inputs.iter() {
            let x = Scalar::random(&mut self.rng);
            let input = *input != 0u16;
            let c = if input { Scalar::one() } else { Scalar::zero() };
            let r = c * s + x * P;
            self.stream.write_pt(&r)?;
            let k = super::hash_pt(&(x * s), KEYSIZE);
            let c0 = self.stream.read_bytes(nbytes + KEYSIZE)?;
            let c1 = self.stream.read_bytes(nbytes + KEYSIZE)?;
            let c = if input { &c1 } else { &c0 };
            let m = super::decrypt(&k, &c);
            outputs.push(BitVec::from(m));
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    const N: usize = 32;

    fn rand_u8_vec(size: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(size);
        for _ in 0..size {
            v.push(rand::random::<u8>());
        }
        v
    }

    #[test]
    fn test() {
        let m0 = rand_u8_vec(N);
        let m1 = rand_u8_vec(N);
        let m0 = BitVec::from(m0.to_vec());
        let m1 = BitVec::from(m1.to_vec());
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let b = rand::random::<bool>();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        let handler = std::thread::spawn(move || {
            let mut ot = ChouOrlandiOT::new(sender);
            ot.send(&[(m0, m1)]).unwrap();
        });
        let mut ot = ChouOrlandiOT::new(receiver);
        let results = ot.receive(&[b as u16], N * 8).unwrap();
        assert_eq!(results[0], if b { m1_ } else { m0_ });
        handler.join().unwrap();
    }
}
