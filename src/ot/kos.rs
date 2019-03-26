// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::alsz::*;
use crate::errors::Error;
use crate::utils;
use crate::{
    CorrelatedObliviousTransferReceiver, CorrelatedObliviousTransferSender,
    ObliviousTransferReceiver, ObliviousTransferSender, RandomObliviousTransferReceiver,
    RandomObliviousTransferSender,
};
use arrayref::array_ref;
use rand::CryptoRng;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::{cointoss, AesRng, Block, Malicious, SemiHonest};
use std::io::{ErrorKind, Read, Write};

const SSP: usize = 40;

pub struct KosOTSender<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> {
    ot: AlszOTSender<OT>,
}

pub struct KosOTReceiver<OT: ObliviousTransferSender<Msg = Block> + Malicious> {
    ot: AlszOTReceiver<OT>,
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> KosOTSender<OT> {
    #[inline]
    fn send_setup<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let ncols = m + 128 + SSP;
        let qs = self.ot.send_setup(reader, ncols)?;
        // Check correlation
        let mut seed = Block::zero();
        rng.fill_bytes(&mut seed.as_mut());
        let seed = cointoss::send(reader, writer, &[seed])?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut check = (Block::zero(), Block::zero());
        let mut chi = Block::zero();
        for j in 0..ncols {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            rng.fill_bytes(&mut chi.as_mut());
            let tmp = q.clmul(chi);
            check = utils::xor_two_blocks(&check, &tmp);
        }
        let x = Block::read(reader)?;
        let t0 = Block::read(reader)?;
        let t1 = Block::read(reader)?;
        let tmp = x.clmul(self.ot.s_);
        let check = utils::xor_two_blocks(&check, &tmp);
        if check != (t0, t1) {
            println!("Consistency check failed!");
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidData,
                "Consistency check failed",
            )));
        }
        Ok(qs)
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> ObliviousTransferSender
    for KosOTSender<OT>
{
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = AlszOTSender::<OT>::init(reader, writer, rng)?;
        Ok(Self { ot })
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        inputs: &[(Block, Block)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(reader, writer, m, rng)?;
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let y0 = self.ot.hash.tccr_hash(j, q) ^ input.0;
            let q = q ^ self.ot.s_;
            let y1 = self.ot.hash.tccr_hash(j, q) ^ input.1;
            y0.write(&mut writer)?;
            y1.write(&mut writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> CorrelatedObliviousTransferSender
    for KosOTSender<OT>
{
    #[inline]
    fn send_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        deltas: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(reader, writer, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.ot.hash.tccr_hash(j, q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.ot.s_;
            let y = self.ot.hash.tccr_hash(j, q) ^ x1;
            y.write(&mut writer)?;
            out.push((x0, x1));
        }
        writer.flush()?;
        Ok(out)
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> RandomObliviousTransferSender
    for KosOTSender<OT>
{
    #[inline]
    fn send_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let qs = self.send_setup(reader, writer, m, rng)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.ot.hash.tccr_hash(j, q);
            let q = q ^ self.ot.s_;
            let x1 = self.ot.hash.tccr_hash(j, q);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> KosOTReceiver<OT> {
    #[inline]
    fn receive_setup<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<u8>, Error> {
        let m = inputs.len();
        let m_ = m + 128 + SSP;
        let mut r = utils::boolvec_to_u8vec(inputs);
        r.extend((0..(m_ - m) / 8).map(|_| rand::random::<u8>()));
        let ts = self.ot.receive_setup(writer, &r, m_)?;
        // Check correlation
        let mut seed = Block::zero();
        rng.fill_bytes(&mut seed.as_mut());
        let seed = cointoss::receive(reader, writer, &[seed])?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut x = Block::zero();
        let mut t = (Block::zero(), Block::zero());
        let r_ = utils::u8vec_to_boolvec(&r);
        let mut chi = Block::zero();
        for (j, xj) in r_.into_iter().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj = Block::from(*array_ref![tj, 0, 16]);
            rng.fill_bytes(&mut chi.as_mut());
            x = x ^ if xj { chi } else { Block::zero() };
            let tmp = tj.clmul(chi);
            t = utils::xor_two_blocks(&t, &tmp);
        }
        x.write(&mut writer)?;
        t.0.write(&mut writer)?;
        t.1.write(&mut writer)?;
        writer.flush()?;
        Ok(ts)
    }
}

impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> ObliviousTransferReceiver
    for KosOTReceiver<OT>
{
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = AlszOTReceiver::<OT>::init(reader, writer, rng)?;
        Ok(Self { ot })
    }

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        mut reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let ts = self.receive_setup(reader, writer, inputs, rng)?;
        // Output result
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y0 = Block::read(&mut reader)?;
            let y1 = Block::read(&mut reader)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self
                .ot
                .hash
                .tccr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> CorrelatedObliviousTransferReceiver
    for KosOTReceiver<OT>
{
    fn receive_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(reader, writer, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y = Block::read(reader)?;
            let y = if *b { y } else { Block::zero() };
            let h = self
                .ot
                .hash
                .tccr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> RandomObliviousTransferReceiver
    for KosOTReceiver<OT>
{
    fn receive_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(reader, writer, inputs, rng)?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let h = self
                .ot
                .hash
                .tccr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(h);
        }
        Ok(out)
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> SemiHonest for KosOTSender<OT> {}
impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> SemiHonest for KosOTReceiver<OT> {}
impl<OT: ObliviousTransferReceiver<Msg = Block> + Malicious> Malicious for KosOTSender<OT> {}
impl<OT: ObliviousTransferSender<Msg = Block> + Malicious> Malicious for KosOTReceiver<OT> {}
