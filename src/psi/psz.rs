// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::cuckoo::CuckooHash;
use crate::stream;
use crate::Error;
use ocelot::kkrt::{Output, Seed};
use ocelot::{ObliviousPrfReceiver, ObliviousPrfSender};
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::collections::hash_map::DefaultHasher;
use std::io::{Read, Write};
use std::marker::PhantomData;

pub struct PszPsiSender<OPRF: ObliviousPrfSender> {
    _oprf: PhantomData<OPRF>,
}
pub struct PszPsiReceiver<OPRF: ObliviousPrfReceiver> {
    _oprf: PhantomData<OPRF>,
}

const NHASHES: usize = 3;

impl<OPRF> PszPsiSender<OPRF>
where
    OPRF: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>,
{
    pub fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let n = inputs.len();
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        let mut init_states = Vec::with_capacity(NHASHES);
        for _ in 0..NHASHES {
            let state = stream::read_usize(reader)?;
            init_states.push(state as u64);
        }
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let seeds = oprf.send(reader, writer, nbins + stashsize, rng)?;
        for i in 0..NHASHES {
            let mut hs = Vec::with_capacity(n);
            for input in inputs.iter() {
                let idx =
                    CuckooHash::hash_with_state::<DefaultHasher>(input, init_states[i], nbins);
                let out = oprf.compute(&seeds[idx], input);
                hs.push(out);
            }
            for h in hs.iter() {
                h.write(writer)?;
            }
        }
        for j in 0..stashsize {
            let mut ss = Vec::with_capacity(n);
            for input in inputs.iter() {
                let out = oprf.compute(&seeds[nbins + j], input);
                ss.push(out);
            }
            for s in ss.iter() {
                s.write(writer)?;
            }
        }
        writer.flush()?;
        // XXX: get output from receiver
        Ok(())
    }
}

impl<OPRF> PszPsiReceiver<OPRF>
where
    OPRF: ObliviousPrfReceiver<Input = Block, Output = Output>,
{
    pub fn run<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Vec<Output>, Error> {
        let n = inputs.len();
        let nbins = compute_nbins(n);
        let stashsize = 16; // XXX FIXME
        let init_states = (0..NHASHES)
            .map(|_| rand::random::<u64>())
            .collect::<Vec<u64>>();
        stream::write_usize(writer, nbins)?;
        stream::write_usize(writer, stashsize)?;
        for state in init_states.iter() {
            stream::write_usize(writer, *state as usize)?;
        }
        writer.flush()?;
        let mut hash = CuckooHash::<Block>::new(nbins, stashsize, init_states);
        for input in inputs.iter() {
            hash.hash::<DefaultHasher>(input)?;
        }
        hash.fill(&Default::default());
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let outputs = oprf.receive(
            reader,
            writer,
            &hash
                .items
                .iter()
                .map(|item| item.unwrap().0) // This unwrap should *never* fail. If it does that's a bug in this code.b
                .collect::<Vec<Block>>(),
            rng,
        )?;
        let mut intersection = vec![];
        for _ in 0..NHASHES {
            for _ in 0..n {
                let out = Output::read(reader)?;
                if outputs.contains(&out) {
                    intersection.push(out);
                }
            }
        }
        for _ in 0..stashsize {
            for _ in 0..n {
                let out = Output::read(reader)?;
                if outputs.contains(&out) {
                    intersection.push(out);
                }
            }
        }
        intersection.sort();
        intersection.dedup();
        Ok(intersection)
    }
}

#[inline]
fn compute_nbins(n: usize) -> usize {
    let size = (1.2 * (n as f64)).floor() as usize;
    // The OPRF only supports sizes mod 16, so let's fix that!
    if size % 16 != 0 {
        size + (16 - size % 16)
    } else {
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocelot::kkrt;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    type PszSender = PszPsiSender<kkrt::KkrtSender>;
    type PszReceiver = PszPsiReceiver<kkrt::KkrtReceiver>;

    const T: usize = 16;

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    #[test]
    fn test_psi() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_block_vec(T);
        let receiver_inputs = sender_inputs.clone();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            PszSender::run(&mut reader, &mut writer, &sender_inputs, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let intersection =
            PszReceiver::run(&mut reader, &mut writer, &receiver_inputs, &mut rng).unwrap();
        handle.join().unwrap();
        assert_eq!(intersection.len(), T);
    }
}
