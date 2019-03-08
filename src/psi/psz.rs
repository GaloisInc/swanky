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
use scuttlebutt::{AesHash, Block};
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
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        let mut hashes = Vec::with_capacity(NHASHES);
        for _ in 0..NHASHES {
            let state = Block::read(reader)?;
            hashes.push(AesHash::new(state));
        }
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let seeds = oprf.send(reader, writer, nbins + stashsize, rng)?;
        for i in 0..NHASHES {
            for input in inputs.iter() {
                let idx = CuckooHash::hash_with_state(*input, &hashes[i], nbins);
                let out = oprf.compute(&seeds[idx], input);
                out.write(writer)?;
            }
        }
        for j in 0..stashsize {
            for input in inputs.iter() {
                let out = oprf.compute(&seeds[nbins + j], input);
                out.write(writer)?;
            }
        }
        writer.flush()?;
        Ok(())
    }
}

impl<OPRF> PszPsiReceiver<OPRF>
where
    OPRF: ObliviousPrfReceiver<Input = Block, Output = Output>,
{
    pub fn run<R, W, RNG>(
        reader: &mut R,
        writer: &mut W,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Vec<Output>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let n = inputs.len();
        let nbins = compute_nbins(n);
        let stashsize = compute_stashsize(n)?;
        let init_states = (0..NHASHES)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        stream::write_usize(writer, nbins)?;
        stream::write_usize(writer, stashsize)?;
        for state in init_states.iter() {
            state.write(writer)?;
        }
        writer.flush()?;
        let mut tbl = CuckooHash::new(nbins, stashsize, init_states);
        for input in inputs.iter() {
            tbl.hash(*input)?;
        }
        tbl.fill(Default::default());
        let mut oprf = OPRF::init(reader, writer, rng)?;
        let outputs = oprf.receive(
            reader,
            writer,
            &tbl.items
                .into_iter()
                .filter_map(|x| x)
                .collect::<Vec<Block>>(),
            rng,
        )?;
        let mut outputs = outputs
            .iter()
            .map(|x| Some(x))
            .collect::<Vec<Option<&Output>>>();
        let mut intersection = Vec::with_capacity(n);
        for _ in 0..NHASHES {
            for _ in 0..n {
                let out = Output::read(reader)?;
                match outputs.iter_mut().find(|&&mut x| x == Some(&out)) {
                    Some(item) => {
                        *item = None;
                        intersection.push(out)
                    }
                    None => (),
                }
            }
        }
        for _ in 0..stashsize {
            for _ in 0..n {
                let out = Output::read(reader)?;
                match outputs.iter_mut().find(|&&mut x| x == Some(&out)) {
                    Some(item) => {
                        *item = None;
                        intersection.push(out)
                    }
                    None => (),
                }
            }
        }
        Ok(intersection)
    }
}

#[inline]
fn compute_nbins(n: usize) -> usize {
    (2.4 * (n as f64)).ceil() as usize
}
#[inline]
fn compute_stashsize(n: usize) -> Result<usize, Error> {
    let stashsize = if n <= 1 << 8 {
        12
    } else if n <= 1 << 12 {
        6
    } else if n <= 1 << 16 {
        4
    } else if n <= 1 << 20 {
        3
    } else if n <= 1 << 24 {
        2
    } else {
        return Err(Error::InvalidInputLength);
    };
    Ok(stashsize)
}

use ocelot::kkrt;

pub type PszSender = PszPsiSender<kkrt::KkrtSender>;
pub type PszReceiver = PszPsiReceiver<kkrt::KkrtReceiver>;

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const T: usize = 1 << 8;

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
