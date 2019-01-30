use super::{ObliviousTransfer, Stream};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct ChouOrlandiOT<T: Read + Write + Send> {
    stream: Stream<T>,
    rng: ThreadRng,
}

impl<T: Read + Write + Send> ObliviousTransfer<T> for ChouOrlandiOT<T> {
    fn new(stream: Arc<Mutex<T>>) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error> {
        let hash = if nbytes == 16 {
            super::hash_pt_128
        } else {
            super::hash_pt
        };
        let y = Scalar::random(&mut self.rng);
        let s = &y * &RISTRETTO_BASEPOINT_TABLE;
        self.stream.write_pt(&s)?;
        for input in inputs.into_iter() {
            let r = self.stream.read_pt()?;
            let k0 = hash(&(&r * &y), nbytes);
            let k1 = hash(&((&r - &s) * &y), nbytes);
            let c0 = encrypt(&k0, &input.0);
            let c1 = encrypt(&k1, &input.1);
            self.stream.write_bytes(&c0)?;
            self.stream.write_bytes(&c1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        let hash = if nbytes == 16 {
            super::hash_pt_128
        } else {
            super::hash_pt
        };
        let s = self.stream.read_pt()?;
        inputs
            .into_iter()
            .map(|b| {
                let x = Scalar::random(&mut self.rng);
                let c = if *b { Scalar::one() } else { Scalar::zero() };
                let r = &c * &s + &x * &RISTRETTO_BASEPOINT_TABLE;
                self.stream.write_pt(&r)?;
                let k = hash(&(&x * &s), nbytes);
                let c0 = self.stream.read_bytes(nbytes)?;
                let c1 = self.stream.read_bytes(nbytes)?;
                let c = if *b { &c1 } else { &c0 };
                let m = decrypt(&k, &c);
                Ok(m)
            })
            .collect()
    }
}

#[inline(always)]
fn encrypt(k: &[u8], m: &[u8]) -> Vec<u8> {
    super::xor(&k, &m)
}
#[inline(always)]
fn decrypt(k: &[u8], c: &[u8]) -> Vec<u8> {
    super::xor(&k, &c)
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
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => panic!("Couldn't create pair of sockets: {:?}", e),
        };
        let handle = std::thread::spawn(move || {
            let mut ot = ChouOrlandiOT::new(sender);
            ot.send(&[(m0, m1)], N).unwrap();
        });
        let mut ot = ChouOrlandiOT::new(receiver);
        let results = ot.receive(&[b], N).unwrap();
        assert_eq!(results[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
