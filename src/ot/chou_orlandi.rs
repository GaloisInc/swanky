use super::{ObliviousTransfer, Stream};
use crate::utils;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Implementation of the Chou-Orlandi semi-honest secure oblivious transfer
/// protocol (cf. <https://eprint.iacr.org/2015/267>).
///
/// This implementation uses the Ristretto prime order elliptic curve group from
/// the `curve25519-dalek` library.
pub struct ChouOrlandiOT<S: Read + Write + Send> {
    stream: Stream<S>,
    rng: ThreadRng,
}

impl<S: Read + Write + Send> ObliviousTransfer<S> for ChouOrlandiOT<S> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error> {
        let hash_inplace = if nbytes == 16 {
            utils::hash_pt_128_inplace
        } else {
            utils::hash_pt_inplace
        };
        let y = Scalar::random(&mut self.rng);
        let s = &y * &RISTRETTO_BASEPOINT_TABLE;
        self.stream.write_pt(&s)?;
        let mut k0 = vec![0u8; nbytes];
        let mut k1 = vec![0u8; nbytes];
        for input in inputs.iter() {
            let r = self.stream.read_pt()?;
            hash_inplace(&(r * y), &mut k0);
            hash_inplace(&((r - s) * y), &mut k1);
            encrypt_inplace(&mut k0, &input.0);
            encrypt_inplace(&mut k1, &input.1);
            self.stream.write_bytes(&k0)?;
            self.stream.write_bytes(&k1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        let hash = if nbytes == 16 {
            utils::hash_pt_128
        } else {
            utils::hash_pt
        };
        let s = self.stream.read_pt()?;
        inputs
            .iter()
            .map(|b| {
                let x = Scalar::random(&mut self.rng);
                let c = if *b { Scalar::one() } else { Scalar::zero() };
                let r = c * s + &x * &RISTRETTO_BASEPOINT_TABLE;
                self.stream.write_pt(&r)?;
                let mut k = hash(&(x * s), nbytes);
                let c0 = self.stream.read_bytes(nbytes)?;
                let c1 = self.stream.read_bytes(nbytes)?;
                let c = if *b { &c1 } else { &c0 };
                decrypt_inplace(&mut k, &c);
                Ok(k)
            })
            .collect()
    }
}

#[inline(always)]
fn encrypt_inplace(mut k: &mut [u8], m: &[u8]) {
    utils::xor_inplace(&mut k, &m)
}
#[inline(always)]
fn decrypt_inplace(mut k: &mut [u8], c: &[u8]) {
    utils::xor_inplace(&mut k, &c)
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
