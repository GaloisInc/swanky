// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::rand_aes::AesRng;
use crate::stream;
use crate::{Block, Malicious, ObliviousTransfer, SemiHonest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
/// <https://eprint.iacr.org/2015/267>).
///
/// This implementation uses the Ristretto prime order elliptic curve group from
/// the `curve25519-dalek` library and works over blocks rather than arbitrary
/// length messages.
///
/// This version fixes a bug in the current ePrint write-up (Page 4): if the
/// value `x^i` produced by the receiver is not randomized, all the random-OTs
/// produced by the protocol will be the same. We fix this by hashing in `i`
/// during the key derivation phase.
pub struct ChouOrlandiOT<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    rng: AesRng,
}

impl<R: Read + Send, W: Write + Send> ObliviousTransfer<R, W> for ChouOrlandiOT<R, W> {
    type Msg = Block;

    fn new() -> Self {
        let rng = AesRng::new();
        Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            rng,
        }
    }

    fn send(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let y = Scalar::random(&mut self.rng);
        let s = &y * &RISTRETTO_BASEPOINT_TABLE;
        stream::write_pt(writer, &s)?;
        writer.flush()?;
        let mut rs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let r = stream::read_pt(reader)?;
            rs.push(r);
        }
        for (i, (input, r)) in inputs.iter().zip(rs.into_iter()).enumerate() {
            let k0 = Block::hash_pt(i, &(r * y));
            let k1 = Block::hash_pt(i, &((r - s) * y));
            let c0 = k0 ^ input.0;
            let c1 = k1 ^ input.1;
            c0.write(writer)?;
            c1.write(writer)?;
        }
        writer.flush()?;
        Ok(())
    }

    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let s = stream::read_pt(reader)?;
        let mut xs = Vec::with_capacity(inputs.len());
        for b in inputs.iter() {
            let x = Scalar::random(&mut self.rng);
            let c = if *b { Scalar::one() } else { Scalar::zero() };
            let r = c * s + &x * &RISTRETTO_BASEPOINT_TABLE;
            stream::write_pt(writer, &r)?;
            xs.push(x);
        }
        writer.flush()?;
        inputs
            .iter()
            .zip(xs.into_iter())
            .enumerate()
            .map(|(i, (b, x))| {
                let k = Block::hash_pt(i, &(x * s));
                let c0 = Block::read(reader)?;
                let c1 = Block::read(reader)?;
                let c = if *b { c1 } else { c0 };
                let c = k ^ c;
                Ok(c)
            })
            .collect()
    }
}

impl<R: Read, W: Write> SemiHonest for ChouOrlandiOT<R, W> {}
impl<R: Read, W: Write> Malicious for ChouOrlandiOT<R, W> {}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::io::{BufReader, BufWriter};
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
            let mut ot = ChouOrlandiOT::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            ot.send(&mut reader, &mut writer, &[(m0, m1)]).unwrap();
        });
        let mut ot = ChouOrlandiOT::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let result = ot.receive(&mut reader, &mut writer, &[b]).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
