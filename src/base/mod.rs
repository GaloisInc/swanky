pub mod chou_orlandi;
pub mod dummy;
pub mod naor_pinkas;

use aesni::block_cipher_trait::generic_array::GenericArray;
use aesni::block_cipher_trait::BlockCipher;
use aesni::Aes128;
use bitvec::BitVec;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use std::io::{Error, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait ObliviousTransfer {
    fn send(&mut self, values: (&BitVec, &BitVec)) -> Result<(), Error>;
    fn receive(&mut self, input: bool, nbits: usize) -> Result<BitVec, Error>;
}

struct Stream<T: Read + Write> {
    stream: Arc<Mutex<T>>,
}

impl<T: Read + Write> Stream<T> {
    pub fn new(stream: T) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        Self { stream }
    }
    #[inline(always)]
    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream().write(pt.compress().as_bytes())
    }
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Unable to decompress point",
                ));
            }
        };
        Ok(pt)
    }
    #[inline(always)]
    fn write_bool(&mut self, b: &bool) -> Result<usize, Error> {
        self.stream().write(&[*b as u8])
    }
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool, Error> {
        let mut data = [0; 1];
        self.stream().read_exact(&mut data)?;
        Ok(if data[0] == 0 { false } else { true })
    }
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.stream().write(bytes)
    }
    #[inline(always)]
    fn read_bytes(&mut self, nbytes: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![0; nbytes];
        self.stream().read_exact(&mut bytes)?;
        Ok(bytes)
    }
    #[inline(always)]
    fn write_bitvec(&mut self, bytes: &BitVec) -> Result<usize, Error> {
        self.stream().write(&(bitvec_to_vec(bytes)))
    }
    #[inline(always)]
    fn read_bitvec(&mut self, nbits: usize) -> Result<BitVec, Error> {
        let mut bytes = vec![0; nbits / 8];
        self.stream().read_exact(&mut bytes)?;
        Ok(BitVec::from(bytes))
    }
}

fn bitvec_to_vec(bytes: &BitVec) -> Vec<u8> {
    let v = bytes.clone().into_iter().collect::<Vec<bool>>();
    let v = v
        .into_boxed_slice()
        .chunks(8)
        .map(|bits| {
            let b = bits.into_iter().enumerate().fold(0u8, |acc, (i, b)| {
                let acc = acc ^ (u8::from(*b) << (7 - i));
                acc
            });
            b
        })
        .collect::<Vec<u8>>();
    v
}

#[inline(always)]
fn hash_pt(pt: &RistrettoPoint, length: usize) -> Vec<u8> {
    if length > 32 {
        panic!("lengths > 32 not yet supported")
    }
    let pt = pt.compress();
    pt.as_bytes()[0..length].to_vec()
}
#[inline(always)]
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "lengths not equal: {} ≠ {}",
        a.len(),
        b.len()
    );
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
#[inline(always)]
fn encrypt(k: &[u8], m: &[u8]) -> Vec<u8> {
    if m.len() != 16 {
        panic!("lengths ≠ 16 not yet supported")
    }
    let cipher = Aes128::new(GenericArray::from_slice(k));
    let mut m = GenericArray::clone_from_slice(m);
    cipher.encrypt_block(&mut m);
    m.to_vec()
}
#[inline(always)]
fn decrypt(k: &[u8], c: &[u8]) -> Vec<u8> {
    if c.len() != 16 {
        panic!("lengths ≠ 16 not yet supported")
    }
    let cipher = Aes128::new(GenericArray::from_slice(k));
    let mut c = GenericArray::clone_from_slice(c);
    cipher.decrypt_block(&mut c);
    c.to_vec()
}
