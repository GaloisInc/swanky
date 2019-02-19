// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

use crate::{stream, utils};
use crate::{
    CorrelatedObliviousTransferReceiver, CorrelatedObliviousTransferSender,
    ObliviousTransferReceiver, ObliviousTransferSender, RandomObliviousTransferReceiver,
    RandomObliviousTransferSender, SemiHonest,
};
use arrayref::array_ref;
use failure::Error;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::{AesHash, AesRng, Block};
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;

/// Oblivious transfer sender.
pub struct AlszOTSender<
    R: Read,
    W: Write,
    OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest,
> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    _ot: PhantomData<OT>,
    hash: AesHash,
    s: Vec<bool>,
    s_: Block,
    rngs: Vec<AesRng>,
}
/// Oblivious transfer receiver.
pub struct AlszOTReceiver<
    R: Read,
    W: Write,
    OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest,
> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    _ot: PhantomData<OT>,
    hash: AesHash,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest>
    AlszOTSender<R, W, OT>
{
    #[inline(always)]
    fn send_setup(&mut self, reader: &mut R, m: usize) -> Result<Vec<u8>, Error> {
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let (nrows, ncols) = (128, m);
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, mut rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            stream::read_bytes_inplace(reader, &mut u)?;
            if !b {
                std::mem::replace(&mut u, vec![0u8; ncols / 8]);
            };
            let rng = &mut rng;
            rng.fill_bytes(&mut q);
            utils::xor_inplace(&mut q, &u);
        }
        Ok(utils::transpose(&qs, nrows, ncols))
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest>
    ObliviousTransferSender<R, W> for AlszOTSender<R, W, OT>
{
    type Msg = Block;

    fn init(reader: &mut R, writer: &mut W) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let mut ot = OT::init(reader, writer)?;
        let hash = AesHash::new(Block::fixed_key());
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        let s = utils::u8vec_to_boolvec(&s_);
        let ks = ot.receive(reader, writer, &s)?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            _ot: PhantomData::<OT>,
            hash,
            s,
            s_: Block::from(s_),
            rngs,
        })
    }

    fn send(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(reader, m)?;
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let y0 = self.hash.cr_hash(j, q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = self.hash.cr_hash(j, q) ^ input.1;
            y0.write(&mut writer)?;
            y1.write(&mut writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest>
    CorrelatedObliviousTransferSender<R, W> for AlszOTSender<R, W, OT>
{
    fn send_correlated(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        deltas: &[Self::Msg],
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(reader, m)?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.hash.cr_hash(j, q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.s_;
            let y = self.hash.cr_hash(j, q) ^ x1;
            y.write(&mut writer)?;
            out.push((x0, x1));
        }
        writer.flush()?;
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest>
    RandomObliviousTransferSender<R, W> for AlszOTSender<R, W, OT>
{
    fn send_random(
        &mut self,
        reader: &mut R,
        _: &mut W,
        m: usize,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let qs = self.send_setup(reader, m)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.hash.cr_hash(j, q);
            let q = q ^ self.s_;
            let x1 = self.hash.cr_hash(j, q);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest>
    AlszOTReceiver<R, W, OT>
{
    #[inline(always)]
    fn receive_setup(&mut self, mut writer: &mut W, inputs: &[bool]) -> Result<Vec<u8>, Error> {
        let m = inputs.len();
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let (nrows, ncols) = (128, m);
        let r = utils::boolvec_to_u8vec(inputs);
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for j in 0..self.rngs.len() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t = &mut ts[range];
            self.rngs[j].0.fill_bytes(&mut t);
            self.rngs[j].1.fill_bytes(&mut g);
            utils::xor_inplace(&mut g, &t);
            utils::xor_inplace(&mut g, &r);
            stream::write_bytes(&mut writer, &g)?;
            writer.flush()?;
        }
        Ok(utils::transpose(&ts, nrows, ncols))
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest>
    ObliviousTransferReceiver<R, W> for AlszOTReceiver<R, W, OT>
{
    type Msg = Block;

    fn init(reader: &mut R, writer: &mut W) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let mut ot = OT::init(reader, writer)?;
        let hash = AesHash::new(Block::fixed_key());
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::zero();
        let mut k1 = Block::zero();
        for _ in 0..128 {
            rng.fill_bytes(&mut k0.as_mut());
            rng.fill_bytes(&mut k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(reader, writer, &ks)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            _ot: PhantomData::<OT>,
            hash,
            rngs,
        })
    }

    fn receive(
        &mut self,
        mut reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(writer, inputs)?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y0 = Block::read(&mut reader)?;
            let y1 = Block::read(&mut reader)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.cr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest>
    CorrelatedObliviousTransferReceiver<R, W> for AlszOTReceiver<R, W, OT>
{
    fn receive_correlated(
        &mut self,
        mut reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(writer, inputs)?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y = Block::read(&mut reader)?;
            let y = if *b { y } else { Block::zero() };
            let h = self.hash.cr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest>
    RandomObliviousTransferReceiver<R, W> for AlszOTReceiver<R, W, OT>
{
    fn receive_random(
        &mut self,
        _: &mut R,
        writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.receive_setup(writer, inputs)?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let h = self.hash.cr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(h);
        }
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + SemiHonest> SemiHonest
    for AlszOTSender<R, W, OT>
{
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + SemiHonest> SemiHonest
    for AlszOTReceiver<R, W, OT>
{
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const T: usize = 1 << 12;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    #[test]
    fn test_otext() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = AlszOTSender::<
                BufReader<UnixStream>,
                BufWriter<UnixStream>,
                chou_orlandi::ChouOrlandiOTReceiver<BufReader<UnixStream>, BufWriter<UnixStream>>,
            >::init(&mut reader, &mut writer)
            .unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut reader, &mut writer, &ms).unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = AlszOTReceiver::<
            BufReader<UnixStream>,
            BufWriter<UnixStream>,
            chou_orlandi::ChouOrlandiOTSender<BufReader<UnixStream>, BufWriter<UnixStream>>,
        >::init(&mut reader, &mut writer)
        .unwrap();
        let results = otext.receive(&mut reader, &mut writer, &bs).unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { m1s_[j] } else { m0s_[j] })
        }
        handle.join().unwrap();
    }

    #[test]
    fn test_cotext() {
        let deltas = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = AlszOTSender::<
                BufReader<UnixStream>,
                BufWriter<UnixStream>,
                chou_orlandi::ChouOrlandiOTReceiver<BufReader<UnixStream>, BufWriter<UnixStream>>,
            >::init(&mut reader, &mut writer)
            .unwrap();
            let mut out = out.lock().unwrap();
            *out = otext
                .send_correlated(&mut reader, &mut writer, &deltas)
                .unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = AlszOTReceiver::<
            BufReader<UnixStream>,
            BufWriter<UnixStream>,
            chou_orlandi::ChouOrlandiOTSender<BufReader<UnixStream>, BufWriter<UnixStream>>,
        >::init(&mut reader, &mut writer)
        .unwrap();
        let results = otext
            .receive_correlated(&mut reader, &mut writer, &bs)
            .unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    #[test]
    fn test_rotext() {
        let bs = rand_bool_vec(T);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = AlszOTSender::<
                BufReader<UnixStream>,
                BufWriter<UnixStream>,
                chou_orlandi::ChouOrlandiOTReceiver<BufReader<UnixStream>, BufWriter<UnixStream>>,
            >::init(&mut reader, &mut writer)
            .unwrap();
            let mut out = out.lock().unwrap();
            *out = otext.send_random(&mut reader, &mut writer, T).unwrap();
        });
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut otext = AlszOTReceiver::<
            BufReader<UnixStream>,
            BufWriter<UnixStream>,
            chou_orlandi::ChouOrlandiOTSender<BufReader<UnixStream>, BufWriter<UnixStream>>,
        >::init(&mut reader, &mut writer)
        .unwrap();
        let results = otext.receive_random(&mut reader, &mut writer, &bs).unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }
}
