// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Zohner private set intersection
//! protocol (cf. <https://eprint.iacr.org/2014/447>) as specified by
//! Kolesnikov-Kumaresan-Rosulek-Trieu (cf. <https://eprint.iacr.org/2016/799>).

use crate::cuckoo::CuckooHash;
use crate::stream;
use crate::Error;
use crate::{PrivateSetIntersectionReceiver, PrivateSetIntersectionSender};
use ocelot::kkrt::{Output, Seed};
use ocelot::{ObliviousPrfReceiver, ObliviousPrfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use scuttlebutt::{AesHash, Block};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Private set intersection sender.
pub struct PszPsiSender<OPRF: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>> {
    oprf: OPRF,
}
/// Private set intersection receiver.
pub struct PszPsiReceiver<OPRF: ObliviousPrfReceiver<Seed = Seed, Input = Block, Output = Output>> {
    oprf: OPRF,
}

/// Specifies the number of hash functions to use in the cuckoo hash.
const NHASHES: usize = 2;

impl<OPRF> PrivateSetIntersectionSender for PszPsiSender<OPRF>
where
    OPRF: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>,
{
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = OPRF::init(reader, writer, rng)?;
        Ok(Self { oprf })
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        let inputs = compress_inputs(inputs);
        let mut hashes = Vec::with_capacity(NHASHES);
        let mut hindices = Vec::with_capacity(NHASHES);
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        for i in 0..NHASHES {
            let state = Block::read(reader)?;
            hashes.push(AesHash::new(state));
            let index = Block::from(i as u128);
            hindices.push(index);
        }
        let seeds = self.oprf.send(reader, writer, nbins + stashsize, rng)?;
        // For each `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x) | x ∈ X)}`,
        // randomly permute it, and send it to the receiver.
        for (hash, index) in hashes.into_iter().zip(hindices.into_iter()) {
            let mut outputs = inputs
                .iter()
                .map(|input| {
                    let idx = CuckooHash::hash_with_state(*input, &hash, nbins);
                    let input = *input ^ index;
                    self.oprf.compute(&seeds[idx], &input)
                })
                .collect::<Vec<Output>>();
            outputs.shuffle(&mut rng);
            for output in outputs.into_iter() {
                output.write(writer)?;
            }
            writer.flush()?;
        }
        // For each `j ∈ {1, ..., stashsize}`, construct set `Sⱼ =
        // {F(k_{nbins+j}, x) | x ∈ X}`, randomly permute it, and send it to the
        // receiver.
        for j in 0..stashsize {
            let mut outputs = inputs
                .iter()
                .map(|input| self.oprf.compute(&seeds[nbins + j], input))
                .collect::<Vec<Output>>();
            outputs.shuffle(&mut rng);
            for output in outputs.into_iter() {
                output.write(writer)?;
            }
        }
        writer.flush()?;
        Ok(())
    }
}

impl<OPRF> PrivateSetIntersectionReceiver for PszPsiReceiver<OPRF>
where
    OPRF: ObliviousPrfReceiver<Seed = Seed, Input = Block, Output = Output>,
{
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = OPRF::init(reader, writer, rng)?;
        Ok(Self { oprf })
    }

    fn receive<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let inputs_ = compress_inputs(inputs);
        let hindices = (0..NHASHES)
            .map(|i| Block::from(i as u128))
            .collect::<Vec<Block>>();
        let n = inputs.len();
        let nbins = compute_nbins(n);
        let stashsize = compute_stashsize(n)?;
        stream::write_usize(writer, nbins)?;
        stream::write_usize(writer, stashsize)?;
        let states = (0..NHASHES)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        let tbl = make_hash_table(nbins, stashsize, &inputs_, &states)?;
        for state in states.into_iter() {
            state.write(writer)?;
        }
        writer.flush()?;
        let inputs_ = tbl
            .items
            .iter()
            .filter_map(|(item, _, hidx)| {
                if let Some(item) = item {
                    if *hidx == usize::max_value() {
                        Some(*item)
                    } else {
                        Some(*item ^ hindices[*hidx])
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<Block>>();
        let outputs = self.oprf.receive(reader, writer, &inputs_, rng)?;
        // Map `outputs` to tuple containing (OPRF output, input index) for
        // outputs that correspond to valid inputs and not dummy values, split
        // by hash index.
        let mut outputs_bin = (0..NHASHES)
            .map(|_| Vec::with_capacity(nbins))
            .collect::<Vec<Vec<(Output, usize)>>>();
        let mut outputs_stash = Vec::with_capacity(stashsize);
        for (output, item) in outputs.into_iter().zip(tbl.items.into_iter()) {
            let (_, idx, hidx) = item;
            if hidx != usize::max_value() {
                outputs_bin[hidx].push((output, idx));
            } else if idx != usize::max_value() {
                outputs_stash.push((output, idx))
            }
        }
        let mut intersection = Vec::with_capacity(n);
        for outputs in outputs_bin.iter_mut() {
            for _ in 0..n {
                let out = Output::read(reader)?;
                for (out_, idx) in outputs.iter_mut() {
                    if out == *out_ {
                        *out_ = Output::default();
                        intersection.push(inputs[*idx].clone());
                        break; // XXX: timing attack
                    }
                }
            }
        }
        let outputs = &mut outputs_stash;
        for _ in 0..stashsize {
            for _ in 0..n {
                let out = Output::read(reader)?;
                for (out_, idx) in outputs.iter_mut() {
                    if out == *out_ {
                        *out_ = Output::default();
                        intersection.push(inputs[*idx].clone());
                        break; // XXX: timing attack!
                    }
                }
            }
        }
        Ok(intersection)
    }
}

// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
// as zero. We need to leave 8 bits free in order to add in the hash index when
// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
fn compress_inputs(inputs: &[Vec<u8>]) -> Vec<Block> {
    let mut compressed = Vec::with_capacity(inputs.len());
    for input in inputs.iter() {
        let mut digest = [0u8; 16];
        if input.len() < 16 {
            // Map `input` directly to a `Block`
            for (byte, result) in input.into_iter().zip(digest.iter_mut()) {
                *result = *byte;
            }
        } else {
            // Hash `input` first
            let mut hasher = Sha256::new();
            hasher.input(input);
            let h = hasher.result();
            for (result, byte) in digest.iter_mut().zip(h.into_iter()) {
                *result = byte;
            }
            digest[15] = 0u8;
        }
        compressed.push(Block::from(digest));
    }
    compressed
}

#[inline]
fn make_hash_table(
    nbins: usize,
    stashsize: usize,
    inputs: &[Block],
    states: &[Block],
) -> Result<CuckooHash, Error> {
    let mut tbl = CuckooHash::new(nbins, stashsize, states);
    for (j, input) in inputs.iter().enumerate() {
        tbl.hash(*input, j)?;
    }
    tbl.fill(Default::default());
    Ok(tbl)
}

#[inline]
fn compute_nbins(n: usize) -> usize {
    (2.4 * (n as f64)).ceil() as usize
}
#[inline]
fn compute_stashsize(n: usize) -> Result<usize, Error> {
    let stashsize = if n <= 1 << 8 {
        8
    } else if n <= 1 << 12 {
        5
    } else if n <= 1 << 16 {
        3
    } else if n <= 1 << 28 {
        2
    } else if n <= 1 << 32 {
        4
    } else {
        return Err(Error::InvalidInputLength);
    };
    Ok(stashsize)
}

use ocelot::kkrt;

/// The PSI sender using the KKRT oblivious PRF under-the-hood.
pub type PszSender = PszPsiSender<kkrt::KkrtSender>;
/// The PSI receiver using the KKRT oblivious PRF under-the-hood.
pub type PszReceiver = PszPsiReceiver<kkrt::KkrtReceiver>;

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 8;

    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
        (0..size).map(|_| rand_vec(SIZE)).collect()
    }

    #[test]
    fn test_psi() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(NTIMES);
        let receiver_inputs = sender_inputs.clone();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut psi = PszSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            psi.send(&mut reader, &mut writer, &sender_inputs, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut psi = PszReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let intersection = psi
            .receive(&mut reader, &mut writer, &receiver_inputs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        assert_eq!(intersection.len(), NTIMES);
    }
}
