// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::stream;
use crate::utils;
use crate::{Block, BlockObliviousTransfer};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use rand::rngs::ThreadRng;
use std::io::{BufReader, BufWriter, Read, Write};
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

impl<S: Read + Write + Send + Sync> BlockObliviousTransfer<S> for NaorPinkasOT<S> {
    fn new() -> Self {
        let rng = rand::thread_rng();
        Self {
            _s: PhantomData::<S>,
            rng,
        }
    }

    fn send(
        &mut self,
        reader: &mut BufReader<S>,
        writer: &mut BufWriter<S>,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut pk0s = Vec::with_capacity(m);
        for _ in 0..m {
            let c = RistrettoPoint::random(&mut self.rng);
            stream::write_pt(writer, &c)?;
            cs.push(c);
        }
        writer.flush()?;
        for _ in 0..m {
            let pk0 = stream::read_pt(reader)?;
            pk0s.push(pk0);
        }
        for (i, ((input, c), pk0)) in inputs
            .into_iter()
            .zip(cs.into_iter())
            .zip(pk0s.into_iter())
            .enumerate()
        {
            let pk1 = c - pk0;
            let r0 = Scalar::random(&mut self.rng);
            let r1 = Scalar::random(&mut self.rng);
            let e00 = &r0 * &RISTRETTO_BASEPOINT_TABLE;
            let e10 = &r1 * &RISTRETTO_BASEPOINT_TABLE;
            let h = utils::hash_pt_block(i, &(pk0 * r0));
            let e01 = utils::xor_block(&h, &input.0);
            let h = utils::hash_pt_block(i, &(pk1 * r1));
            let e11 = utils::xor_block(&h, &input.1);
            stream::write_pt(writer, &e00)?;
            stream::write_block(writer, &e01)?;
            stream::write_pt(writer, &e10)?;
            stream::write_block(writer, &e11)?;
        }
        writer.flush()?;
        Ok(())
    }

    fn receive(
        &mut self,
        reader: &mut BufReader<S>,
        writer: &mut BufWriter<S>,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut ks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = stream::read_pt(reader)?;
            cs.push(c);
        }
        for (b, c) in inputs.into_iter().zip(cs.into_iter()) {
            let k = Scalar::random(&mut self.rng);
            let pkσ = &k * &RISTRETTO_BASEPOINT_TABLE;
            let pkσ_ = c - pkσ;
            match b {
                false => stream::write_pt(writer, &pkσ)?,
                true => stream::write_pt(writer, &pkσ_)?,
            };
            ks.push(k);
        }
        writer.flush()?;
        inputs
            .into_iter()
            .zip(ks.into_iter())
            .enumerate()
            .map(|(i, (b, k))| {
                let e00 = stream::read_pt(reader)?;
                let e01 = stream::read_block(reader)?;
                let e10 = stream::read_pt(reader)?;
                let e11 = stream::read_block(reader)?;
                let (eσ0, eσ1) = match b {
                    false => (e00, e01),
                    true => (e10, e11),
                };
                let h = utils::hash_pt_block(i, &(eσ0 * k));
                let m = utils::xor_block(&h, &eσ1);
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

    #[test]
    fn test() {
        let m0 = rand::random::<Block>();
        let m1 = rand::random::<Block>();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut ot = NaorPinkasOT::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            ot.send(&mut reader, &mut writer, &[(m0, m1)]).unwrap();
        });
        let mut ot = NaorPinkasOT::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let result = ot.receive(&mut reader, &mut writer, &[b]).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
