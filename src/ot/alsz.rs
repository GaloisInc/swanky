// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

use crate::hash_aes::AesHash;
use crate::rand_aes::AesRng;
use crate::{stream, utils};
use crate::{Block, ObliviousTransferReceiver, ObliviousTransferSender, SemiHonest};
use arrayref::array_ref;
use failure::Error;
use rand_core::{RngCore, SeedableRng};
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;

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
    s_: [u8; 16],
    rngs: Vec<AesRng>,
}

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
            s_,
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
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let (nrows, ncols) = (128, m);
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        let rngs = &mut self.rngs;
        for (j, (b, mut rng)) in self.s.iter().zip(rngs.into_iter()).enumerate() {
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
        let mut qs = utils::transpose(&qs, nrows, ncols);
        for (j, input) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            let y0 = self.hash.cr_hash(j, Block::from(*array_ref![q, 0, 16])) ^ input.0;
            utils::xor_inplace(&mut q, &self.s_);
            let y1 = self.hash.cr_hash(j, Block::from(*array_ref![q, 0, 16])) ^ input.1;
            y0.write(&mut writer)?;
            y1.write(&mut writer)?;
        }
        writer.flush()?;
        Ok(())
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
        mut writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Self::Msg>, Error> {
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
        let ts = utils::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(ncols);
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = &ts[range];
            let y0 = Block::read(&mut reader)?;
            let y1 = Block::read(&mut reader)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.cr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y);
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
    use itertools::izip;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const T: usize = 1 << 12;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    #[test]
    fn test() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
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
        for (b, result, m0, m1) in izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(result, if b { m1 } else { m0 })
        }
        handle.join().unwrap();
    }
}
