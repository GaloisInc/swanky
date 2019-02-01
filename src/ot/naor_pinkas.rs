use crate::stream::Stream;
use crate::utils;
use crate::ObliviousTransfer;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{Read, Write};

/// Implementation of the Naor-Pinkas semi-honest secure oblivious transfer
/// protocol.
///
/// This implementation uses the Ristretto prime order elliptic curve group from
/// the `curve25519-dalek` library.
pub struct NaorPinkasOT<T: Read + Write + Send> {
    stream: Stream<T>,
    rng: ThreadRng,
}

impl<T: Read + Write + Send> ObliviousTransfer<T> for NaorPinkasOT<T> {
    fn new(stream: T) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error> {
        for input in inputs.iter() {
            let c = RistrettoPoint::random(&mut self.rng);
            self.stream.write_pt(&c)?;
            let pk0 = self.stream.read_pt()?;
            let pk1 = c - pk0;
            let r0 = Scalar::random(&mut self.rng);
            let r1 = Scalar::random(&mut self.rng);
            let e00 = &r0 * &RISTRETTO_BASEPOINT_TABLE;
            let e10 = &r1 * &RISTRETTO_BASEPOINT_TABLE;
            let h = utils::hash_pt(&(pk0 * r0), nbytes);
            let e01 = utils::xor(&h, &input.0);
            let h = utils::hash_pt(&(pk1 * r1), nbytes);
            let e11 = utils::xor(&h, &input.1);
            self.stream.write_pt(&e00)?;
            self.stream.write_bytes(&e01)?;
            self.stream.write_pt(&e10)?;
            self.stream.write_bytes(&e11)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        inputs
            .iter()
            .map(|input| {
                let c = self.stream.read_pt()?;
                let k = Scalar::random(&mut self.rng);
                let pkσ = &k * &RISTRETTO_BASEPOINT_TABLE;
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
                let h = utils::hash_pt(&(eσ0 * k), nbytes);
                let m = utils::xor(&h, &eσ1);
                Ok(m)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    const N: usize = 16;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>().to_vec();
        let m1 = rand::random::<[u8; N]>().to_vec();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handler = std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new(sender);
            ot.send(&[(m0, m1)], N).unwrap();
        });
        let mut ot = NaorPinkasOT::new(receiver);
        let result = ot.receive(&[b], N).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handler.join().unwrap();
    }
}
