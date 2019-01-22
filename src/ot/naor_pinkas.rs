use super::{ObliviousTransfer, Stream};
use bitvec::BitVec;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::cmp::max;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct NaorPinkasOT<T: Read + Write> {
    stream: Stream<T>,
    rng: ThreadRng,
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write> NaorPinkasOT<T> {
    fn _send(&mut self, values: &(BitVec, BitVec)) -> Result<(), Error> {
        let length = max(values.0.len(), values.1.len()) / 8;
        let c = RistrettoPoint::random(&mut self.rng);
        self.stream.write_pt(&c)?;
        let pk0 = self.stream.read_pt()?;
        let pk1 = c - pk0;
        let r0 = Scalar::random(&mut self.rng);
        let r1 = Scalar::random(&mut self.rng);
        let e00 = P * r0;
        let e10 = P * r1;
        let h = super::hash_pt(&(pk0 * r0), length);
        let e01 = super::xor(&h, &super::bitvec_to_vec(&values.0));
        let h = super::hash_pt(&(pk1 * r1), length);
        let e11 = super::xor(&h, &super::bitvec_to_vec(&values.1));
        self.stream.write_pt(&e00)?;
        self.stream.write_bytes(&e01)?;
        self.stream.write_pt(&e10)?;
        self.stream.write_bytes(&e11)?;
        Ok(())
    }

    fn _receive(&mut self, input: u16, nbits: usize) -> Result<BitVec, Error> {
        let input = match input {
            0 => false,
            1 => true,
            _ => {
                return Err(Error::from(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Input must be zero or one",
                )));
            }
        };
        let nbytes = nbits / 8;
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
        let h = super::hash_pt(&(eσ0 * k), nbits / 8);
        let result = super::xor(&h, &eσ1);
        Ok(BitVec::from(result))
    }
}

impl<T: Read + Write> ObliviousTransfer<T> for NaorPinkasOT<T> {
    fn new(stream: Arc<Mutex<T>>) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, values: &[(BitVec, BitVec)]) -> Result<(), Error> {
        for inputs in values.iter() {
            self._send(inputs)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[u16], nbits: usize) -> Result<Vec<BitVec>, Error> {
        let mut outputs = Vec::with_capacity(inputs.len());
        for input in inputs.iter() {
            let output = self._receive(*input, nbits)?;
            outputs.push(output);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    const N: usize = 32;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>();
        let m1 = rand::random::<[u8; N]>();
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
        std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new(sender);
            ot.send(&[(m0, m1)]).unwrap();
        });
        let mut ot = NaorPinkasOT::new(receiver);
        let result = ot.receive(&[b as u16], N * 8).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
