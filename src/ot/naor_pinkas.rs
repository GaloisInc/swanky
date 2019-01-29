use super::{ObliviousTransfer, Stream};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::cmp::max;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct NaorPinkasOT<T: Read + Write + Send> {
    stream: Stream<T>,
    rng: ThreadRng,
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write + Send> ObliviousTransfer<T> for NaorPinkasOT<T> {
    fn new(stream: Arc<Mutex<T>>) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
        for input in inputs.iter() {
            let nbytes = max(input.0.len(), input.1.len());
            let c = RistrettoPoint::random(&mut self.rng);
            self.stream.write_pt(&c)?;
            let pk0 = self.stream.read_pt()?;
            let pk1 = c - pk0;
            let r0 = Scalar::random(&mut self.rng);
            let r1 = Scalar::random(&mut self.rng);
            let e00 = P * r0;
            let e10 = P * r1;
            let mut h = vec![0u8; nbytes];
            hash_pt(&(pk0 * r0), &mut h);
            let m: Vec<u8> = input.0.clone().into();
            let e01 = super::xor(&h, &m);
            let mut h = vec![0u8; nbytes];
            hash_pt(&(pk1 * r1), &mut h);
            let m: Vec<u8> = input.1.clone().into();
            let e11 = super::xor(&h, &m);
            self.stream.write_pt(&e00)?;
            self.stream.write_bytes(&e01)?;
            self.stream.write_pt(&e10)?;
            self.stream.write_bytes(&e11)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        let mut outputs = Vec::with_capacity(inputs.len());
        for input in inputs.iter() {
            let c = self.stream.read_pt()?;
            let k = Scalar::random(&mut self.rng);
            let pkσ = P * k;
            let pkσ_ = c - pkσ;
            match input {
                false => self.stream.write_pt(&pkσ)?,
                true => self.stream.write_pt(&pkσ_)?,
            };
            let e00 = self.stream.read_pt()?;
            let e01 = self.stream.read_bytes(nbytes)?;
            let e10 = self.stream.read_pt()?;
            let e11 = self.stream.read_bytes(nbytes)?;
            let (eσ0, eσ1) = match input {
                false => (e00, e01),
                true => (e10, e11),
            };
            let mut h = vec![0u8; nbytes];
            hash_pt(&(eσ0 * k), &mut h);
            let result = super::xor(&h, &eσ1);
            outputs.push(result);
        }
        Ok(outputs)
    }
}

#[inline(always)]
fn hash_pt(pt: &RistrettoPoint, h: &mut [u8]) {
    let k = pt.compress();
    let k = k.as_bytes();
    super::encrypt(&k[0..16], &[0u8; 16], h)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    const N: usize = 32;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>().to_vec();
        let m1 = rand::random::<[u8; N]>().to_vec();
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
        std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new(sender);
            ot.send(&[(m0, m1)]).unwrap();
        });
        let mut ot = NaorPinkasOT::new(receiver);
        let result = ot.receive(&[b], N).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
    }
}
