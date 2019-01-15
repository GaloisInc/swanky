use super::ObliviousTransfer;
use std::io::{Error, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

pub struct NaorPinkasOT<T: Read + Write> {
    stream: Arc<Mutex<T>>
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write> NaorPinkasOT<T> {
    pub fn new(stream: Arc<Mutex<T>>) -> Self {
        Self { stream }
    }

    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }

    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream().write(pt.compress().as_bytes())
    }

    fn write_u128(&mut self, data: &u128) -> Result<usize, Error> {
        self.stream().write(&data.to_ne_bytes())
    }

    fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => return Err(Error::new(ErrorKind::InvalidData, "Unable to decompress point")),
        };
        Ok(pt)
    }

    fn read_u128(&mut self) -> Result<u128, Error> {
        let mut data = [0; 16];
        self.stream().read_exact(&mut data)?;
        Ok(u128::from_ne_bytes(data))
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
        self.write_pt(&c)?;
        let pk0 = self.read_pt()?;
        let pk1 = c - pk0;
        let r0 = Scalar::random(&mut rng);
        let r1 = Scalar::random(&mut rng);
        let e00 = P * r0;
        let e10 = P * r1;
        let h = (pk0 * r0).compress().to_bytes();
        let e01 = u128::from_ne_bytes(*array_ref!(h, 0, 16)) ^ values[0];
        let h = (pk1 * r1).compress().to_bytes();
        let e11 = u128::from_ne_bytes(*array_ref!(h, 0, 16)) ^ values[1];
        self.write_pt(&e00)?;
        self.write_u128(&e01)?;
        self.write_pt(&e10)?;
        self.write_u128(&e11)?;
        Ok(())
    }

    fn receive(&mut self, input: usize) -> Result<u128, Error> {
        if input != 0 && input != 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "Input must be zero or one"));
        }
        let mut rng = rand::thread_rng();
        let c = self.read_pt()?;
        let k = Scalar::random(&mut rng);
        let pkσ = P * k;
        let pkσ_ = c - pkσ;
        match input {
            0 => self.write_pt(&pkσ)?,
            1 => self.write_pt(&pkσ_)?,
            _ => panic!(),
        };
        let e00 = self.read_pt()?;
        let e01 = self.read_u128()?;
        let e10 = self.read_pt()?;
        let e11 = self.read_u128()?;
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
            let mut ot = NaorPinkasOT::new(Arc::new(Mutex::new(sender)));
            ot.send(vec![m0, m1]).unwrap();
        });
        let mut ot = NaorPinkasOT::new(Arc::new(Mutex::new(receiver)));
        let result = ot.receive(b as usize).unwrap();
        assert_eq!(result, if b { m1 } else { m0 });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
