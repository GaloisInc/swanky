// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use crate::stream;
use crate::{Malicious, ObliviousTransferReceiver, ObliviousTransferSender, SemiHonest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use failure::Error;
use scuttlebutt::{AesRng, Block};
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Oblivious transfer sender.
pub struct ChouOrlandiOTSender<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    y: Scalar,
    s: RistrettoPoint,
}

impl<R: Read + Send, W: Write + Send> ObliviousTransferSender<R, W> for ChouOrlandiOTSender<R, W> {
    type Msg = Block;

    fn init(_: &mut R, writer: &mut W) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let y = Scalar::random(&mut rng);
        let s = &y * &RISTRETTO_BASEPOINT_TABLE;
        stream::write_pt(writer, &s)?;
        writer.flush()?;
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            y,
            s,
        })
    }

    fn send(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let mut ks = Vec::with_capacity(inputs.len());
        for i in 0..inputs.len() {
            let r = stream::read_pt(reader)?;
            let k0 = Block::hash_pt(i, &(self.y * r));
            let k1 = Block::hash_pt(i, &(self.y * (r - self.s)));
            ks.push((k0, k1));
        }
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            c0.write(writer)?;
            c1.write(writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

/// Oblivious transfer receiver.
pub struct ChouOrlandiOTReceiver<R: Read, W: Write> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    rng: AesRng,
    s: RistrettoBasepointTable,
}

impl<R: Read + Send, W: Write + Send> ObliviousTransferReceiver<R, W>
    for ChouOrlandiOTReceiver<R, W>
{
    type Msg = Block;

    fn init(reader: &mut R, _: &mut W) -> Result<Self, Error> {
        let rng = AesRng::new();
        let s = stream::read_pt(reader)?;
        let s = RistrettoBasepointTable::create(&s);
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            rng,
            s,
        })
    }

    fn receive(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let mut ks = Vec::with_capacity(inputs.len());
        for (i, b) in inputs.iter().enumerate() {
            let x = Scalar::random(&mut self.rng);
            let c = if *b { Scalar::one() } else { Scalar::zero() };
            let r = &c * &self.s + &x * &RISTRETTO_BASEPOINT_TABLE;
            stream::write_pt(writer, &r)?;
            ks.push(Block::hash_pt(i, &(&x * &self.s)));
        }
        writer.flush()?;
        inputs
            .iter()
            .zip(ks.into_iter())
            .map(|(b, k)| {
                let c0 = Block::read(reader)?;
                let c1 = Block::read(reader)?;
                let c = if *b { c1 } else { c0 };
                let c = k ^ c;
                Ok(c)
            })
            .collect()
    }
}

impl<R: Read, W: Write> SemiHonest for ChouOrlandiOTSender<R, W> {}
impl<R: Read, W: Write> Malicious for ChouOrlandiOTSender<R, W> {}
impl<R: Read, W: Write> SemiHonest for ChouOrlandiOTReceiver<R, W> {}
impl<R: Read, W: Write> Malicious for ChouOrlandiOTReceiver<R, W> {}

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
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut ot = ChouOrlandiOTSender::init(&mut reader, &mut writer).unwrap();
            ot.send(&mut reader, &mut writer, &[(m0, m1)]).unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut ot = ChouOrlandiOTReceiver::init(&mut reader, &mut writer).unwrap();
        let result = ot.receive(&mut reader, &mut writer, &[b]).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
