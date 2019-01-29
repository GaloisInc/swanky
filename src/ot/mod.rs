mod alsz;
mod chou_orlandi;
mod dummy;
mod iknp;
mod naor_pinkas;

pub use alsz::AlszOT;
pub use chou_orlandi::ChouOrlandiOT;
pub use dummy::DummyOT;
pub use iknp::IknpOT;
pub use naor_pinkas::NaorPinkasOT;

use aesni::block_cipher_trait::BlockCipher;
use aesni::stream_cipher::generic_array::GenericArray;
use aesni::stream_cipher::{NewStreamCipher, StreamCipher};
use aesni::{Aes128, Aes128Ctr};
use bitvec::{BitVec, LittleEndian};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use failure::Error;
use std::io::Error as IOError;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait ObliviousTransfer<T: Read + Write + Send> {
    fn new(stream: Arc<Mutex<T>>) -> Self;
    fn send(&mut self, values: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error>;
    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error>;
}

struct Stream<T: Read + Write + Send> {
    stream: Arc<Mutex<T>>,
}

impl<T: Read + Write + Send> Stream<T> {
    pub fn new(stream: Arc<Mutex<T>>) -> Self {
        Self { stream }
    }
    #[inline(always)]
    fn stream(&mut self) -> MutexGuard<T> {
        self.stream.lock().unwrap()
    }
    #[inline(always)]
    fn write_pt(&mut self, pt: &RistrettoPoint) -> Result<usize, Error> {
        self.stream()
            .write(pt.compress().as_bytes())
            .map_err(Error::from)
    }
    #[inline(always)]
    fn read_pt(&mut self) -> Result<RistrettoPoint, Error> {
        let mut data = [0; 32];
        self.stream().read_exact(&mut data)?;
        let pt = match CompressedRistretto::from_slice(&data).decompress() {
            Some(pt) => pt,
            None => {
                return Err(Error::from(IOError::new(
                    ErrorKind::InvalidData,
                    "Unable to decompress point",
                )));
            }
        };
        Ok(pt)
    }
    #[inline(always)]
    fn write_bool(&mut self, b: bool) -> Result<usize, Error> {
        self.stream().write(&[b as u8]).map_err(Error::from)
    }
    #[inline(always)]
    fn read_bool(&mut self) -> Result<bool, Error> {
        let mut data = [0; 1];
        self.stream().read_exact(&mut data)?;
        Ok(data[0] != 0)
    }
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.stream().write(bytes).map_err(Error::from)
    }
    #[inline(always)]
    fn read_bytes(&mut self, nbytes: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0; nbytes];
        self.stream().read_exact(&mut v)?;
        Ok(v)
    }
    #[inline(always)]
    fn write_u128(&mut self, data: &u128) -> Result<usize, Error> {
        self.stream()
            .write(&data.to_le_bytes())
            .map_err(Error::from)
    }
    #[inline(always)]
    fn read_u128(&mut self) -> Result<u128, Error> {
        let mut data = [0; 16];
        self.stream().read_exact(&mut data)?;
        Ok(u128::from_ne_bytes(data))
    }
}

#[inline(always)]
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "xor lengths not equal: {} ≠ {}",
        a.len(),
        b.len()
    );
    a.into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

type Cipher = Aes128Ctr;
type BV = BitVec<LittleEndian>;

#[inline(always)]
fn encrypt(k: &[u8], iv: &[u8], mut m: &mut [u8]) {
    let mut cipher = Cipher::new_var(k, iv).unwrap();
    cipher.encrypt(&mut m)
}

#[inline(always)]
fn transpose(m: &[Vec<u8>], ℓ: usize) -> Vec<u128> {
    (0..ℓ)
        .map(|i| {
            let bv = m
                .iter()
                .map(|v| BV::from(v.clone()))
                .map(|v: BV| v.get(i).unwrap())
                .collect::<BV>();
            let v: Vec<u8> = bv.into();
            u8vec_to_u128(&v)
        })
        .collect()
}

#[inline(always)]
fn cipher(iv: &[u8; 16]) -> Aes128 {
    let k = GenericArray::from_slice(iv);
    Aes128::new(&k)
}

#[inline(always)]
fn hash(_i: usize, x: &u128, cipher: &Aes128) -> u128 {
    // XXX: Note that this is only secure in the semi-honest setting!
    let mut c = GenericArray::clone_from_slice(&x.to_le_bytes());
    cipher.encrypt_block(&mut c);
    let c = u8vec_to_u128(&c);
    c ^ x
}
#[inline(always)]
fn boolvec_to_u128(v: &[bool]) -> u128 {
    v.into_iter().enumerate().fold(0u128, |acc, (i, b)| {
        acc | (*b as u128).wrapping_shl(i as u32)
    })
}
#[inline(always)]
fn u8vec_to_u128(v: &[u8]) -> u128 {
    let v = array_ref![v, 0, 16];
    u128::from_ne_bytes(*v)
}
