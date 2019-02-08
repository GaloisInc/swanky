// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::stream;
use crate::utils;
use crate::ObliviousTransfer;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Implementation of the Naor-Pinkas semi-honest secure oblivious transfer
/// protocol.
///
/// This implementation uses the Ristretto prime order elliptic curve group from
/// the `curve25519-dalek` library.
pub struct NaorPinkasOT<S: Read + Write + Send + Sync> {
    _s: PhantomData<S>,
    rng: ThreadRng,
}

impl<S: Read + Write + Send + Sync> ObliviousTransfer<S> for NaorPinkasOT<S> {
    fn new() -> Self {
        let rng = rand::thread_rng();
        Self {
            _s: PhantomData::<S>,
            rng,
        }
    }

    fn send(
        &mut self,
        stream: &mut S,
        inputs: &[(Vec<u8>, Vec<u8>)],
        nbytes: usize,
    ) -> Result<(), Error> {
        for input in inputs.iter() {
            let c = RistrettoPoint::random(&mut self.rng);
            stream::write_pt(stream, &c)?;
            let pk0 = stream::read_pt(stream)?;
            let pk1 = c - pk0;
            let r0 = Scalar::random(&mut self.rng);
            let r1 = Scalar::random(&mut self.rng);
            let e00 = &r0 * &RISTRETTO_BASEPOINT_TABLE;
            let e10 = &r1 * &RISTRETTO_BASEPOINT_TABLE;
            let h = utils::hash_pt(&(pk0 * r0), nbytes);
            let e01 = utils::xor(&h, &input.0);
            let h = utils::hash_pt(&(pk1 * r1), nbytes);
            let e11 = utils::xor(&h, &input.1);
            stream::write_pt(stream, &e00)?;
            stream::write_bytes(stream, &e01)?;
            stream::write_pt(stream, &e10)?;
            stream::write_bytes(stream, &e11)?;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        stream: &mut S,
        inputs: &[bool],
        nbytes: usize,
    ) -> Result<Vec<Vec<u8>>, Error> {
        inputs
            .iter()
            .map(|input| {
                let c = stream::read_pt(stream)?;
                let k = Scalar::random(&mut self.rng);
                let pkσ = &k * &RISTRETTO_BASEPOINT_TABLE;
                let pkσ_ = c - pkσ;
                match input {
                    false => stream::write_pt(stream, &pkσ)?,
                    true => stream::write_pt(stream, &pkσ_)?,
                };
                let e00 = stream::read_pt(stream)?;
                let e01 = stream::read_bytes(stream, nbytes)?;
                let e10 = stream::read_pt(stream)?;
                let e11 = stream::read_bytes(stream, nbytes)?;
                let (eσ0, eσ1) = match input {
                    false => (e00, e01),
                    true => (e10, e11),
                };
                let h = utils::hash_pt(&(eσ0 * k), nbytes);
                let m = utils::xor(&h, &eσ1);
                Ok(m)
            })
            .collect()
    }
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
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let handler = std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new();
            ot.send(&mut sender, &[(m0, m1)], N).unwrap();
        });
        let mut ot = NaorPinkasOT::new();
        let result = ot.receive(&mut receiver, &[b], N).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handler.join().unwrap();
    }
}
