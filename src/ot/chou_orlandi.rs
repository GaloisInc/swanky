use super::{ObliviousTransfer, Stream};
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
const IVSIZE: usize = 16;

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
            let mut k0 = vec![0u8; KEYSIZE];
            let mut k1 = vec![0u8; KEYSIZE];
            super::hash_pt(&(r * y), &mut k0);
            super::hash_pt(&((r - s) * y), &mut k1);
            let iv0 = rand::random::<[u8; IVSIZE]>();
            let mut c0: Vec<u8> = input.0.clone().into();
            super::encrypt(&k0, &iv0, &mut c0);
            let iv1 = rand::random::<[u8; IVSIZE]>();
            let mut c1: Vec<u8> = input.1.clone().into();
            super::encrypt(&k1, &iv1, &mut c1);
            self.stream.write_bytes(&iv0)?;
            self.stream.write_bytes(&c0)?;
            self.stream.write_bytes(&iv1)?;
            self.stream.write_bytes(&c1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbits: usize) -> Result<Vec<BitVec>, Error> {
        let nbytes = nbits / 8;
        let mut outputs = Vec::with_capacity(inputs.len());
        let s = self.stream.read_pt()?;
        for input in inputs.iter() {
            let x = Scalar::random(&mut self.rng);
            let c = if *input {
                Scalar::one()
            } else {
                Scalar::zero()
            };
            let r = c * s + x * P;
            self.stream.write_pt(&r)?;
            let mut k = vec![0u8; KEYSIZE];
            super::hash_pt(&(x * s), &mut k);
            let iv0 = self.stream.read_bytes(IVSIZE)?;
            let c0 = self.stream.read_bytes(nbytes)?;
            let iv1 = self.stream.read_bytes(IVSIZE)?;
            let c1 = self.stream.read_bytes(nbytes)?;
            let iv = if *input { &iv1 } else { &iv0 };
            let m = if *input { &c1 } else { &c0 };
            let mut m = m.clone();
            super::decrypt(&k, &iv, &mut m);
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

    #[test]
    fn test() {
        let m00 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let m01 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let m10 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let m11 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let b0 = rand::random::<bool>();
        let b1 = rand::random::<bool>();
        let m00_ = m00.clone();
        let m01_ = m01.clone();
        let m10_ = m10.clone();
        let m11_ = m11.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        let handler = std::thread::spawn(move || {
            let mut ot = ChouOrlandiOT::new(sender);
            ot.send(&[
                (BitVec::from(m00), BitVec::from(m01)),
                (BitVec::from(m10), BitVec::from(m11)),
            ])
            .unwrap();
        });
        let mut ot = ChouOrlandiOT::new(receiver);
        let results = ot.receive(&[b0, b1], N * 8).unwrap();
        assert_eq!(
            results[0],
            BitVec::<bitvec::BigEndian>::from(if b0 { m01_ } else { m00_ })
        );
        assert_eq!(
            results[1],
            BitVec::<bitvec::BigEndian>::from(if b1 { m11_ } else { m10_ })
        );
        handler.join().unwrap();
    }
}
