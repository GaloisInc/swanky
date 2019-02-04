// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::hash_aes::AesHash;
use crate::stream;
use crate::utils;
use crate::{Block, BlockObliviousTransfer, ObliviousTransfer};
use arrayref::array_ref;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// Implementation of the Ishai-Killian-Nissim-Petrank semi-honest secure
/// oblivious transfer extension protocol (cf.
/// <https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1432/1432.pdf>).
pub struct IknpOT<S: Read + Write + Send, OT: ObliviousTransfer<S>> {
    _s: PhantomData<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: Read + Write + Send, OT: ObliviousTransfer<S>> BlockObliviousTransfer<S> for IknpOT<S, OT> {
    fn new() -> Self {
        let ot = OT::new();
        let rng = rand::thread_rng();
        Self {
            _s: PhantomData::<S>,
            ot,
            rng,
        }
    }

    fn send(&mut self, stream: &mut S, inputs: &[(Block, Block)]) -> Result<(), Error> {
        assert_eq!(
            inputs.len() % 8,
            0,
            "Number of inputs must be divisible by 8"
        );
        if inputs.len() <= 128 {
            // Just do normal OT
            return self.ot.send(
                stream,
                &inputs
                    .iter()
                    .map(|(a, b)| (a.to_vec(), b.to_vec()))
                    .collect::<Vec<(Vec<u8>, Vec<u8>)>>(),
                16,
            );
        }
        let (nrows, ncols) = (128, inputs.len());
        let hash = AesHash::new(&[0u8; 16]);
        let s = (0..128)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let qs = self.ot.receive(stream, &s, ncols / 8)?;
        let qs = qs.into_iter().flatten().collect::<Vec<u8>>();
        let mut qs = utils::transpose(&qs, nrows, ncols);
        let s = utils::boolvec_to_u8vec(&s);
        for (j, input) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            let y0 = utils::xor_block(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.0);
            utils::xor_inplace(&mut q, &s);
            let y1 = utils::xor_block(&hash.cr_hash(j, array_ref![q, 0, 16]), &input.1);
            stream::write_block(stream, &y0)?;
            stream::write_block(stream, &y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, stream: &mut S, inputs: &[bool]) -> Result<Vec<Block>, Error> {
        if inputs.len() <= 128 {
            // Just do normal OT
            let v = self.ot.receive(stream, inputs, 16)?;
            return Ok(v.into_iter().map(|b| *array_ref![b, 0, 16]).collect());
        }
        let (nrows, ncols) = (128, inputs.len());
        let hash = AesHash::new(&[0u8; 16]);
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = (0..128)
            .map(|_| {
                let bv = (0..inputs.len())
                    .map(|_| self.rng.gen::<bool>())
                    .collect::<Vec<bool>>();
                utils::boolvec_to_u8vec(&bv)
            })
            .map(|t| (t.clone(), utils::xor(&t, &r)))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(stream, &ts, inputs.len() / 8)?;
        let ts = ts.into_iter().flat_map(|(t, _)| t).collect::<Vec<u8>>();
        let ts = utils::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = &ts[range];
            let y0 = stream::read_block(stream)?;
            let y1 = stream::read_block(stream)?;
            let y = if *b { y1 } else { y0 };
            let r = utils::xor_block(&y, &hash.cr_hash(j, array_ref![t, 0, 16]));
            out.push(r);
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

    const N: usize = 1 << 12;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OT: ObliviousTransfer<UnixStream>>(n: usize) {
        let m0s = rand_block_vec(n);
        let m1s = rand_block_vec(n);
        let bs = rand_bool_vec(n);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut otext = IknpOT::<UnixStream, OT>::new();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut sender, &ms).unwrap();
        });
        let mut otext = IknpOT::<UnixStream, OT>::new();
        let results = otext.receive(&mut receiver, &bs).unwrap();
        for (b, result, m0, m1) in izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(result, if b { m1 } else { m0 })
        }
    }

    #[test]
    fn test() {
        test_ot::<DummyOT<UnixStream>>(N);
    }
}
