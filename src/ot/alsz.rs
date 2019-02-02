// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::hash_aes::AesHash;
use crate::rand_aes::AesRng;
use crate::stream::{CloneStream, Stream};
use crate::utils;
use crate::{Block, BlockObliviousTransfer};
use arrayref::array_ref;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{ErrorKind, Read, Write};

/// Implementation of the Asharov-Lindell-Schneider-Zohner semi-honest secure
/// oblivious transfer extension protocol (cf.
/// <https://eprint.iacr.org/2016/602>, Protocol 4).
pub struct AlszOT<S: CloneStream + Read + Write + Send, OT: BlockObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: CloneStream + Read + Write + Send, OT: BlockObliviousTransfer<S>> BlockObliviousTransfer<S>
    for AlszOT<S, OT>
{
    fn new(stream: S) -> Self {
        let ot = OT::new(stream.try_clone().unwrap());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, inputs: &[(Block, Block)]) -> Result<(), Error> {
        let m = inputs.len();
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        if m <= 128 {
            // Just do normal OT
            return self.ot.send(inputs);
        }
        let (nrows, ncols) = (128, m);
        let hash = AesHash::new(&[0u8; 16]); // XXX IV should be chosen at random
        let s = (0..nrows)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let s_ = utils::boolvec_to_u8vec(&s);
        let ks = self.ot.receive(&s)?;
        let rngs = ks.into_iter().map(|k| AesRng::new(&k));
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, rng)) in s.into_iter().zip(rngs).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            self.stream.read_bytes_inplace(&mut u)?;
            let u = if b { u.clone() } else { vec![0u8; ncols / 8] };
            rng.random(&mut q);
            utils::xor_inplace(&mut q, &u);
        }
        let mut qs = utils::transpose(&qs, nrows, ncols);
        for (j, input) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            let y0 = utils::xor_block(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.0);
            utils::xor_inplace(&mut q, &s_);
            let y1 = utils::xor_block(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.1);
            self.stream.write_block(&y0)?;
            self.stream.write_block(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool]) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        if m <= 128 {
            // Just do normal OT
            return self.ot.receive(inputs);
        }
        let (nrows, ncols) = (128, m);
        let hash = AesHash::new(&[0u8; 16]); // XXX IV should be chosen at random
        let ks = (0..nrows)
            .map(|_| (self.rng.gen::<Block>(), self.rng.gen::<Block>()))
            .collect::<Vec<(Block, Block)>>();
        self.ot.send(&ks)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::new(&k0), AesRng::new(&k1)));
        let r = utils::boolvec_to_u8vec(inputs);
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for (j, (rng0, rng1)) in rngs.enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t = &mut ts[range];
            rng0.random(&mut t);
            rng1.random(&mut g);
            utils::xor_inplace(&mut g, &t);
            utils::xor_inplace(&mut g, &r);
            self.stream.write_bytes(&g)?;
        }
        let ts = utils::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(ncols);
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = &ts[range];
            let y0 = self.stream.read_block()?;
            let y1 = self.stream.read_block()?;
            let y = if *b { y1 } else { y0 };
            let y = utils::xor_block(&y, &hash.cr_hash(j, array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
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

    fn test_ot<OT: BlockObliviousTransfer<UnixStream>>() {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let bs = rand_bool_vec(T);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut otext = AlszOT::<UnixStream, OT>::new(sender);
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&ms).unwrap();
        });
        let mut otext = AlszOT::<UnixStream, OT>::new(receiver);
        let results = otext.receive(&bs).unwrap();
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
