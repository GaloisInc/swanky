// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::hash_aes::AesHash;
use crate::rand_aes::AesRng;
use crate::{block, commit, stream, utils};
use crate::{Block, BlockObliviousTransfer, Malicious};
use arrayref::array_ref;
use failure::Error;
use rand_core::{RngCore, SeedableRng};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::marker::PhantomData;

pub struct KosOT<S: Read + Write + Send + Sync, OT: BlockObliviousTransfer<S> + Malicious> {
    _placeholder: PhantomData<S>,
    ot: OT,
    rng: AesRng,
    hash: AesHash,
}

const SSP: usize = 40;

impl<S: Read + Write + Send + Sync, OT: BlockObliviousTransfer<S> + Malicious>
    BlockObliviousTransfer<S> for KosOT<S, OT>
{
    fn new() -> Self {
        let ot = OT::new();
        let rng = AesRng::new();
        let hash = AesHash::new(&super::FIXED_KEY);
        Self {
            _placeholder: PhantomData::<S>,
            ot,
            rng,
            hash,
        }
    }

    fn send(
        &mut self,
        reader: &mut BufReader<S>,
        mut writer: &mut BufWriter<S>,
        inputs: &[(Block, Block)],
    ) -> Result<(), Error> {
        let ℓ = inputs.len();
        if ℓ % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        if ℓ <= 128 {
            // Just do normal OT
            return self.ot.send(reader, writer, inputs);
        }
        let ℓ_ = ℓ + 128 + SSP;
        let (nrows, ncols) = (128, ℓ_);
        let mut δ_ = vec![0u8; nrows / 8];
        self.rng.fill_bytes(&mut δ_);
        let δ = utils::u8vec_to_boolvec(&δ_);
        let ks = self.ot.receive(reader, writer, &δ)?;
        let rngs = ks.into_iter().map(AesRng::from_seed);
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, mut rng)) in δ.into_iter().zip(rngs).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            rng.fill_bytes(&mut q);
            stream::read_bytes_inplace(reader, &mut u)?;
            if !b {
                std::mem::replace(&mut u, vec![0u8; ncols / 8]);
            };
            utils::xor_inplace(&mut q, &u);
        }
        let mut qs = utils::transpose(&qs, nrows, ncols);
        // Check correlation
        let mut seed = block::zero_block();
        self.rng.fill_bytes(&mut seed);
        let seed = commit::send(reader, writer, seed)?;
        let mut rng = AesRng::from_seed(seed);
        let mut check = (block::zero_block(), block::zero_block());
        for j in 0..ncols {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let q = &qs[range];
            let q = *array_ref![q, 0, 16];
            let mut χ = block::zero_block();
            rng.fill_bytes(&mut χ);
            let tmp = block::mul128(q, χ);
            check = block::xor_two_blocks(&check, &tmp);
        }
        let mut x = block::zero_block();
        let mut t0 = block::zero_block();
        let mut t1 = block::zero_block();
        stream::read_bytes_inplace(reader, &mut x)?;
        stream::read_bytes_inplace(reader, &mut t0)?;
        stream::read_bytes_inplace(reader, &mut t1)?;
        let tmp = block::mul128(x, *array_ref![δ_, 0, 16]);
        let check = block::xor_two_blocks(&check, &tmp);
        if check.0 != t0 || check.1 != t1 {
            println!("Consistency check failed!");
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidData,
                "Consistency check failed",
            )));
        }
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            let y0 = block::xor_block(&self.hash.tccr_hash(j, array_ref![q, 0, 16]), &input.0);
            utils::xor_inplace(&mut q, &δ_);
            let y1 = block::xor_block(&self.hash.tccr_hash(j, array_ref![q, 0, 16]), &input.1);
            stream::write_block(&mut writer, &y0)?;
            stream::write_block(&mut writer, &y1)?;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        mut reader: &mut BufReader<S>,
        mut writer: &mut BufWriter<S>,
        inputs: &[bool],
    ) -> Result<Vec<Block>, Error> {
        let ℓ = inputs.len();
        if ℓ <= 128 {
            // Just do normal OT
            return self.ot.receive(reader, writer, inputs);
        }
        let ℓ_ = ℓ + 128 + SSP;
        let (nrows, ncols) = (128, ℓ_);
        let mut ks = Vec::with_capacity(nrows);
        let mut k0 = [0u8; 16];
        let mut k1 = [0u8; 16];
        for _ in 0..nrows {
            self.rng.fill_bytes(&mut k0);
            self.rng.fill_bytes(&mut k1);
            ks.push((k0, k1));
        }
        self.ot.send(reader, writer, &ks)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        let mut r = utils::boolvec_to_u8vec(inputs);
        r.extend((0..(ℓ_ - ℓ) / 8).map(|_| rand::random::<u8>()));

        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for (j, (mut rng0, mut rng1)) in rngs.into_iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t = &mut ts[range];
            rng0.fill_bytes(&mut t);
            rng1.fill_bytes(&mut g);
            utils::xor_inplace(&mut g, &t);
            utils::xor_inplace(&mut g, &r);
            stream::write_bytes(&mut writer, &g)?;
            writer.flush()?;
        }
        let ts = utils::transpose(&ts, nrows, ncols);
        // Check correlation
        let mut seed = block::zero_block();
        self.rng.fill_bytes(&mut seed);
        let seed = commit::receive(reader, writer, seed)?;
        let mut rng = AesRng::from_seed(seed);
        let mut x = block::zero_block();
        let mut t = (block::zero_block(), block::zero_block());
        let r_ = utils::u8vec_to_boolvec(&r);
        for (j, xj) in r_.into_iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let tj = &ts[range];
            let tj = *array_ref![tj, 0, 16];
            let mut χ = block::zero_block();
            rng.fill_bytes(&mut χ);
            let tmp = if xj { χ } else { block::zero_block() };
            x = block::xor_block(&x, &tmp);
            let tmp = block::mul128(tj, χ);
            t = block::xor_two_blocks(&t, &tmp);
        }
        stream::write_bytes(&mut writer, &x)?;
        stream::write_bytes(&mut writer, &t.0)?;
        stream::write_bytes(&mut writer, &t.1)?;
        writer.flush()?;
        // Output result
        let mut out = Vec::with_capacity(ncols);
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = &ts[range];
            let y0 = stream::read_block(&mut reader)?;
            let y1 = stream::read_block(&mut reader)?;
            let y = if *b { y1 } else { y0 };
            let y = block::xor_block(&y, &self.hash.tccr_hash(j, array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

impl<S: Read + Write + Send + Sync, OT: BlockObliviousTransfer<S> + Malicious> Malicious
    for KosOT<S, OT>
{
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
    use itertools::izip;
    use std::os::unix::net::UnixStream;

    const T: usize = 1 << 12;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OT: BlockObliviousTransfer<UnixStream> + Malicious>() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut otext = KosOT::<UnixStream, OT>::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut reader, &mut writer, &ms).unwrap();
        });
        let mut otext = KosOT::<UnixStream, OT>::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let results = otext.receive(&mut reader, &mut writer, &bs).unwrap();
        for (b, result, m0, m1) in izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(result, if b { m1 } else { m0 })
        }
        handle.join().unwrap();
    }

    #[test]
    fn test() {
        test_ot::<ChouOrlandiOT<UnixStream>>();
    }
}
