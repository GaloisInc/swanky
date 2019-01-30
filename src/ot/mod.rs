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
    let m = vec![0u8; 16];
    let mut m = GenericArray::clone_from_slice(&m);
    c.encrypt_block(&mut m);
    m.to_vec()
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
fn transpose(m: &[Vec<u8>], ncols: usize) -> Vec<Vec<u8>> {
    // (0..ncols)
    //     .map(|i| {
    //         let c = m
    //             .into_iter()
    //             .map(|r| BV::from(r.clone()))
    //             .map(|r: BV| r.get(i).unwrap())
    //             .collect::<BV>();
    //         let c: Vec<u8> = c.into();
    //         c
    //     })
    //     .collect()
    let nrows = m.len();
    let m: Vec<u8> = m.to_vec().into_iter().flatten().collect::<Vec<u8>>();
    let mut m_ = vec![0u8; nrows * ncols / 8];
    unsafe {
        sse_trans(
            m_.as_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        )
    };
    let mut out = Vec::with_capacity(ncols);
    for _ in 0..(ncols) {
        let r = m_.drain(0..nrows / 8).collect();
        out.push(r);
    }
    out
}
#[inline(always)]
fn _transpose(m: &[u8], ncols: usize) -> Vec<u8> {
    let nrows = m.len();
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
    // let mut out = Vec::with_capacity(ncols);
    // for _ in 0..(ncols) {
    //     let r = m_.drain(0..nrows / 8).collect();
    //     out.push(r);
    // }
    // out
}

#[inline(always)]
fn cipher(k: &[u8; 16]) -> Aes128 {
    let k = GenericArray::from_slice(k);
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

#[link(name = "transpose")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

#[cfg(test)]
mod tests {
    extern crate test;

    #[test]
    fn test_transpose() {
        let nrows = 16;
        let ncols = 16;
        let mut m = Vec::with_capacity(nrows);
        for _ in 0..nrows {
            let row = (0..ncols)
                .map(|_| rand::random::<u8>())
                .collect::<Vec<u8>>();
            m.push(row);
        }
        for r in m.iter() {
            for c in r.iter() {
                print!("{:08b} ", c);
            }
            println!();
        }
        println!();
        let m_ = super::transpose(&m, ncols * 8);
        for r in m_.iter() {
            for c in r.iter() {
                print!("{:08b} ", c);
            }
            println!();
        }
        println!();
        let m__ = super::transpose(&m_, nrows);
        for r in m__.iter() {
            for c in r.iter() {
                print!("{:08b} ", c);
            }
            println!();
        }
        println!();
        assert_eq!(m, m__);
    }
}
