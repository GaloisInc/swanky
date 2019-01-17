use super::{ObliviousTransfer, Stream};
use bitvec::BitVec;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::ThreadRng;
use std::io::{Error, Read, Write};

pub struct ChouOrlandiOT<T: Read + Write> {
    stream: Stream<T>,
    rng: ThreadRng,
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write> ChouOrlandiOT<T> {
    pub fn new(stream: T) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, rng }
    }
}

impl<T: Read + Write> ObliviousTransfer for ChouOrlandiOT<T> {
    fn send(&mut self, values: (&BitVec, &BitVec)) -> Result<(), Error> {
        let length = std::cmp::max(values.0.len() / 8, values.1.len() / 8);
        let a = Scalar::random(&mut self.rng);
        let a_ = P * a;
        self.stream.write_pt(&a_)?;
        let b_ = self.stream.read_pt()?;
        let k0 = super::hash_pt(&(b_ * a), length);
        let k1 = super::hash_pt(&((b_ - a_) * a), length);
        let m0 = super::encrypt(&k0, &super::bitvec_to_vec(values.0));
        let m1 = super::encrypt(&k1, &super::bitvec_to_vec(values.1));
        self.stream.write_bytes(&m0)?;
        self.stream.write_bytes(&m1)?;
        Ok(())
    }

    fn receive(&mut self, input: bool, nbits: usize) -> Result<BitVec, Error> {
        let nbytes = nbits / 8;
        let b = Scalar::random(&mut self.rng);
        let a_ = self.stream.read_pt()?;
        let b_ = match input {
            // XXX: Timing attack!
            false => P * b,
            true => a_ + P * b,
        };
        self.stream.write_pt(&b_)?;
        let kr = super::hash_pt(&(a_ * b), nbytes);
        let c_0 = self.stream.read_bytes(nbytes)?;
        let c_1 = self.stream.read_bytes(nbytes)?;
        let c = if input { &c_1 } else { &c_0 };
        let m = super::decrypt(&kr, &c);
        Ok(BitVec::from(m))
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    const N: usize = 16;
    const TIMES: usize = 128;

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
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        let handler = std::thread::spawn(move || {
            let mut ot = ChouOrlandiOT::new(sender);
            for _ in 0..TIMES {
                ot.send((&m0, &m1)).unwrap();
            }
        });
        let mut ot = ChouOrlandiOT::new(receiver);
        for _ in 0..TIMES {
            let result = ot.receive(b, N * 8).unwrap();
            assert_eq!(&result, if b { &m1_ } else { &m0_ });
        }
        handler.join().unwrap();
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
