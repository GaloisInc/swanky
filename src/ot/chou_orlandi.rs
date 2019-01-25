use super::{ObliviousTransfer, Stream};
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

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
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
            let mut c0 = input.0.clone();
            super::encrypt(&k0, &iv0, &mut c0);
            let iv1 = rand::random::<[u8; IVSIZE]>();
            let mut c1 = input.1.clone();
            super::encrypt(&k1, &iv1, &mut c1);
            self.stream.write_bytes(&iv0)?;
            self.stream.write_bytes(&c0)?;
            self.stream.write_bytes(&iv1)?;
            self.stream.write_bytes(&c1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
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
            outputs.push(m);
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
        let m0 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let m1 = (0..N).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
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
        let results = ot.receive(&[b], N).unwrap();
        assert_eq!(results[0], if b { m1_ } else { m0_ });
        handler.join().unwrap();
    }
}
