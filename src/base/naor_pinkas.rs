use super::{EllipticCurveOT, ObliviousTransfer};
use std::io::{Error, ErrorKind, Read, Write};
use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

pub struct NaorPinkasOT<T: Read + Write> {
    ot: EllipticCurveOT<T>
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write> NaorPinkasOT<T> {
    pub fn new(stream: T) -> Self {
        let ot = EllipticCurveOT::new(stream);
        Self { ot }
    }
}

impl<T: Read + Write> ObliviousTransfer for NaorPinkasOT<T>
{
    fn send(&mut self, values: Vec<u128>) -> Result<(), Error> {
        if values.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "Number of values must be two"));
        }
        let mut rng = rand::thread_rng();
        let c = RistrettoPoint::random(&mut rng);
        self.ot.write_pt(&c)?;
        let pk0 = self.ot.read_pt()?;
        let pk1 = c - pk0;
        let r0 = Scalar::random(&mut rng);
        let r1 = Scalar::random(&mut rng);
        let e00 = P * r0;
        let e10 = P * r1;
        let e01 = self.ot.hash_pt(&(pk0 * r0)) ^ values[0];
        let e11 = self.ot.hash_pt(&(pk1 * r1)) ^ values[1];
        self.ot.write_pt(&e00)?;
        self.ot.write_u128(&e01)?;
        self.ot.write_pt(&e10)?;
        self.ot.write_u128(&e11)?;
        Ok(())
    }

    fn receive(&mut self, input: usize) -> Result<u128, Error> {
        if input != 0 && input != 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "Input must be zero or one"));
        }
        let mut rng = rand::thread_rng();
        let c = self.ot.read_pt()?;
        let k = Scalar::random(&mut rng);
        let pkσ = P * k;
        let pkσ_ = c - pkσ;
        match input {
            0 => self.ot.write_pt(&pkσ)?,
            1 => self.ot.write_pt(&pkσ_)?,
            _ => panic!(),
        };
        let e00 = self.ot.read_pt()?;
        let e01 = self.ot.read_u128()?;
        let e10 = self.ot.read_pt()?;
        let e11 = self.ot.read_u128()?;
        let (eσ0, eσ1) = match input {
            0 => (e00, e01),
            1 => (e10, e11),
            _ => panic!(),
        };
        let h = (eσ0 * k).compress().to_bytes();
        let result = u128::from_ne_bytes(array_ref!(h, 0, 16).clone()) ^ eσ1;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    #[test]
    fn test() {
        let m0 = rand::random::<u128>();
        let m1 = rand::random::<u128>();
        let b = rand::random::<bool>();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return
            }
        };
        std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new(sender);
            ot.send(vec![m0, m1]).unwrap();
        });
        let mut ot = NaorPinkasOT::new(receiver);
        let result = ot.receive(b as usize).unwrap();
        assert_eq!(result, if b { m1 } else { m0 });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
