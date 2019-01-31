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

use crate::aes::{Aes128, AES};
use aesni::stream_cipher::{NewStreamCipher, StreamCipher};
use aesni::Aes128Ctr;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use failure::Error;
use std::io::Error as IOError;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait ObliviousTransfer<T: Read + Write + Send> {
    fn new(stream: Arc<Mutex<T>>) -> Self;
    fn send(&mut self, values: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error>;
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
}

#[inline(always)]
fn hash_pt(pt: &RistrettoPoint, nbytes: usize) -> Vec<u8> {
    let k = pt.compress();
    let k = k.as_bytes();
    let mut m = vec![0u8; nbytes];
    encrypt(&k[0..16], &k[16..32], &mut m);
    m
}

#[inline(always)]
fn hash_pt_128(pt: &RistrettoPoint, _nbytes: usize) -> Vec<u8> {
    let k = pt.compress();
    let k = k.as_bytes();
    let c = cipher(array_ref![k, 0, 16]);
    let m = [0u8; 16];
    let m = c.encrypt_u8(&m);
    m.to_vec()
}

#[inline(always)]
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    // assert_eq!(
    //     a.len(),
    //     b.len(),
    //     "xor lengths not equal: {} ≠ {}",
    //     a.len(),
    //     b.len()
    // );
    a.into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

type Cipher = Aes128Ctr;

#[inline(always)]
fn encrypt(k: &[u8], iv: &[u8], mut m: &mut [u8]) {
    let mut cipher = Cipher::new_var(k, iv).unwrap();
    cipher.encrypt(&mut m)
}
#[inline(always)]
fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    let m_ = vec![0u8; nrows * ncols / 8];
    unsafe {
        sse_trans(
            m_.as_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        )
    };
    m_
}

#[inline(always)]
fn cipher(_k: &[u8; 16]) -> Aes128 {
    AES
}

#[inline(always)]
fn hash(_i: usize, x: &[u8], cipher: &Aes128) -> Vec<u8> {
    // XXX: Note that this is only secure in the semi-honest setting!
    let y = cipher.encrypt_u8(array_ref![x, 0, 16]);
    let r = xor(&x, &y);
    r
}
#[inline(always)]
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let mut v = vec![0u8; bv.len() / 8];
    for (i, b) in bv.into_iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}

#[link(name = "transpose")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}
