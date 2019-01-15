use super::{EllipticCurveOT, ObliviousTransfer};
use aesni::Aes128;
use aesni::block_cipher_trait::BlockCipher;
use aesni::block_cipher_trait::generic_array::GenericArray;
use std::io::{Error, ErrorKind, Read, Write};
use rand::rngs::ThreadRng;
use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

pub struct ChouOrlandiOT<T: Read + Write> {
    ot: EllipticCurveOT<T>,
    rng: ThreadRng,
}

const P: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

impl<T: Read + Write> ChouOrlandiOT<T> {
    pub fn new(stream: T) -> Self {
        let ot = EllipticCurveOT::new(stream);
        let rng = rand::thread_rng();
        Self { ot, rng }
    }
}

impl<T: Read + Write> ObliviousTransfer for ChouOrlandiOT<T>
{
    fn send(&mut self, values: Vec<u128>) -> Result<(), Error> {
        if values.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "Number of values must be two"));
        }
        let a = Scalar::random(&mut self.rng);
        let a_ = P * a;
        self.ot.write_pt(&a_)?;
        let b_ = self.ot.read_pt()?;
        let k0 = self.ot.hash_pt(&(b_ * a));
        let k1 = self.ot.hash_pt(&((b_ - a_) * a));
        let cipher0 = Aes128::new(GenericArray::from_slice(&k0.to_ne_bytes()));
        let cipher1 = Aes128::new(GenericArray::from_slice(&k1.to_ne_bytes()));
        let mut m0 = GenericArray::clone_from_slice(&values[0].to_ne_bytes());
        let mut m1 = GenericArray::clone_from_slice(&values[1].to_ne_bytes());
        cipher0.encrypt_block(&mut m0);
        cipher1.encrypt_block(&mut m1);
        let c0 = array_ref!(m0.as_slice(), 0, 16);
        self.ot.write_u128(&u128::from_ne_bytes(*c0))?;
        let c1 = array_ref!(m1.as_slice(), 0, 16);
        self.ot.write_u128(&u128::from_ne_bytes(*c1))?;
        Ok(())
    }

    fn receive(&mut self, input: usize) -> Result<u128, Error> {
        if input != 0 && input != 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "Input must be zero or one"));
        }
        let b = Scalar::random(&mut self.rng);
        let a_ = self.ot.read_pt()?;
        let b_ = match input {  // XXX: Timing attack!
            0 => P * b,
            1 => a_ + P * b,
            _ => panic!()
        };
        self.ot.write_pt(&b_)?;
        let kr = self.ot.hash_pt(&(a_ * b));
        let cipher = Aes128::new(GenericArray::from_slice(&kr.to_ne_bytes()));
        let c_0 = self.ot.read_u128()?;
        let c_1 = self.ot.read_u128()?;
        let c = if input == 1 { c_1 } else { c_0 };
        let mut c = GenericArray::clone_from_slice(&c.to_ne_bytes());
        cipher.decrypt_block(&mut c);
        let m = array_ref!(c.as_slice(), 0, 16);
        Ok(u128::from_ne_bytes(*m))
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
            let mut ot = ChouOrlandiOT::new(sender);
            ot.send(vec![m0, m1]).unwrap();
        });
        let mut ot = ChouOrlandiOT::new(receiver);
        let result = ot.receive(b as usize).unwrap();
        assert_eq!(result, if b { m1 } else { m0 });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
