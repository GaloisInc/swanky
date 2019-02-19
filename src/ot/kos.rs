// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::{cointoss, stream, utils};
use crate::{Malicious, ObliviousTransferReceiver, ObliviousTransferSender};
use arrayref::array_ref;
use failure::Error;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::{AesHash, AesRng, Block};
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;

const SSP: usize = 40;

pub struct KosOTSender<
    R: Read,
    W: Write,
    OT: ObliviousTransferReceiver<R, W, Msg = Block> + Malicious,
> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    _ot: PhantomData<OT>,
    rng: AesRng,
    hash: AesHash,
    δ: Vec<bool>,
    δ_: Block,
    rngs: Vec<AesRng>,
}

pub struct KosOTReceiver<
    R: Read,
    W: Write,
    OT: ObliviousTransferSender<R, W, Msg = Block> + Malicious,
> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
    _ot: PhantomData<OT>,
    rng: AesRng,
    hash: AesHash,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + Malicious>
    ObliviousTransferSender<R, W> for KosOTSender<R, W, OT>
{
    type Msg = Block;

    fn init(mut reader: &mut R, mut writer: &mut W) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let hash = AesHash::new(Block::fixed_key());
        let mut ot = OT::init(&mut reader, &mut writer)?;
        let mut δ_ = [0u8; 16];
        rng.fill_bytes(&mut δ_);
        let δ = utils::u8vec_to_boolvec(&δ_);
        let ks = ot.receive(reader, writer, &δ)?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
            _ot: PhantomData::<OT>,
            rng,
            hash,
            δ,
            δ_: Block::from(δ_),
            rngs,
        })
    }

    fn send(
        &mut self,
        reader: &mut R,
        mut writer: &mut W,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let ℓ = inputs.len();
        if ℓ % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let ℓ_ = ℓ + 128 + SSP;
        let (nrows, ncols) = (128, ℓ_);
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, rng)) in self.δ.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            rng.fill_bytes(&mut q);
            stream::read_bytes_inplace(reader, &mut u)?;
            if !b {
                std::mem::replace(&mut u, vec![0u8; ncols / 8]);
            };
            utils::xor_inplace(&mut q, &u);
        }
        let qs = utils::transpose(&qs, nrows, ncols);
        // Check correlation
        let mut seed = Block::zero();
        self.rng.fill_bytes(&mut seed.as_mut());
        let seed = cointoss::send(reader, writer, seed)?;
        let mut rng = AesRng::from_seed(seed);
        let mut check = (Block::zero(), Block::zero());
        let mut χ = Block::zero();
        for j in 0..ncols {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            rng.fill_bytes(&mut χ.as_mut());
            let tmp = q.mul128(χ);
            check = utils::xor_two_blocks(&check, &tmp);
        }
        let x = Block::read(reader)?;
        let t0 = Block::read(reader)?;
        let t1 = Block::read(reader)?;
        let tmp = x.mul128(self.δ_);
        let check = utils::xor_two_blocks(&check, &tmp);
        if check != (t0, t1) {
            println!("Consistency check failed!");
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidData,
                "Consistency check failed",
            )));
        }
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let y0 = self.hash.tccr_hash(j, q) ^ input.0;
            let q = q ^ self.δ_;
            let y1 = self.hash.tccr_hash(j, q) ^ input.1;
            y0.write(&mut writer)?;
            y1.write(&mut writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + Malicious>
    ObliviousTransferReceiver<R, W> for KosOTReceiver<R, W, OT>
{
    type Msg = Block;

    fn init(mut reader: &mut R, mut writer: &mut W) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let hash = AesHash::new(Block::fixed_key());
        let mut ot = OT::init(&mut reader, &mut writer)?;
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
            rng,
            hash,
            rngs,
        })
    }

    fn receive(
        &mut self,
        mut reader: &mut R,
        mut writer: &mut W,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let ℓ = inputs.len();
        let ℓ_ = ℓ + 128 + SSP;
        let (nrows, ncols) = (128, ℓ_);
        let mut r = utils::boolvec_to_u8vec(inputs);
        r.extend((0..(ℓ_ - ℓ) / 8).map(|_| rand::random::<u8>()));
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
        }
        writer.flush()?;
        let ts = utils::transpose(&ts, nrows, ncols);
        // Check correlation
        let mut seed = Block::zero();
        self.rng.fill_bytes(&mut seed.as_mut());
        let seed = cointoss::receive(reader, writer, seed)?;
        let mut rng = AesRng::from_seed(seed);
        let mut x = Block::zero();
        let mut t = (Block::zero(), Block::zero());
        let r_ = utils::u8vec_to_boolvec(&r);
        let mut χ = Block::zero();
        for (j, xj) in r_.into_iter().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj = Block::from(*array_ref![tj, 0, 16]);
            rng.fill_bytes(&mut χ.as_mut());
            x = x ^ if xj { χ } else { Block::zero() };
            let tmp = tj.mul128(χ);
            t = utils::xor_two_blocks(&t, &tmp);
        }
        x.write(&mut writer)?;
        t.0.write(&mut writer)?;
        t.1.write(&mut writer)?;
        writer.flush()?;
        // Output result
        let mut out = Vec::with_capacity(ncols);
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y0 = Block::read(&mut reader)?;
            let y1 = Block::read(&mut reader)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.tccr_hash(j, Block::from(*array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

impl<R: Read, W: Write, OT: ObliviousTransferReceiver<R, W, Msg = Block> + Malicious> Malicious
    for KosOTSender<R, W, OT>
{
}
impl<R: Read, W: Write, OT: ObliviousTransferSender<R, W, Msg = Block> + Malicious> Malicious
    for KosOTReceiver<R, W, OT>
{
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
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
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut otext = KosOTSender::<
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
        let mut otext = KosOTReceiver::<
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
}
