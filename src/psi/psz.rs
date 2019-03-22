// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Zohner private set intersection
//! protocol (cf. <https://eprint.iacr.org/2014/447>) as specified by
//! Kolesnikov-Kumaresan-Rosulek-Trieu (cf. <https://eprint.iacr.org/2016/799>).
//!
//! The current implementation does not hash the output of the (relaxed) OPRF.

use crate::cuckoo::{compute_masksize, CuckooHash, NHASHES};
use crate::stream;
use crate::Error;
use crate::{PrivateSetIntersectionReceiver, PrivateSetIntersectionSender};
use ocelot::kkrt::{Output, Seed};
use ocelot::{ObliviousPrfReceiver, ObliviousPrfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use scuttlebutt::utils as scutils;
use scuttlebutt::{Aes128, Block};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::time::SystemTime;

/// Private set intersection sender.
pub struct PszPsiSender<OPRF: ObliviousPrfSender<Seed = Seed, Input = Block, Output = Output>> {
    oprf: OPRF,
}
/// Private set intersection receiver.
pub struct PszPsiReceiver<OPRF: ObliviousPrfReceiver<Seed = Seed, Input = Block, Output = Output>> {
    oprf: OPRF,
}

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
        let key = Block::read(reader)?;
        let aes = Aes128::new(key);
        let mut inputs = compress_and_hash_inputs(inputs, &aes);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        // let start = SystemTime::now();
        let seeds = self.oprf.send(reader, writer, nbins + stashsize, rng)?;
        // eprintln!("[S] OPRF: {} ms", start.elapsed().unwrap().as_millis());
        // For each `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x || i) | x ∈ X)}`,
        // randomly permute it, and send it to the receiver.
        let hindices = (0..NHASHES).map(|i| Block::from(i as u128));
        for (i, hidx) in hindices.enumerate() {
            inputs.shuffle(&mut rng);
            // let start = SystemTime::now();
            for input in inputs.iter() {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(*input, i, nbins);
                let mut encoded = self.oprf.encode(&(*input ^ hidx));
                // Compute rest of `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                scutils::xor_inplace_n(&mut encoded.0, &seeds[bin].0, masksize);
                writer.write_all(&encoded.0[0..masksize])?;
            }
            // eprintln!("[S] Send set: {} ms", start.elapsed().unwrap().as_millis());
        }
        // For each `i ∈ {1, ..., stashsize}`, construct set `Sᵢ =
        // {F(k_{nbins+i}, x) | x ∈ X}`, randomly permute it, and send it to the
        // receiver.
        // let start = SystemTime::now();
        let mut encoded = inputs
            .iter()
            .map(|input| self.oprf.encode(input))
            .collect::<Vec<Output>>();
        // eprintln!("[S] Encode: {} ms", start.elapsed().unwrap().as_millis());
        for i in 0..stashsize {
            encoded.shuffle(&mut rng);
            // let start = SystemTime::now();-
            for encoded in encoded.iter() {
                // We don't need to append any hash index to OPRF inputs in the stash.
                let mut output = vec![0u8; masksize];
                scutils::xor_inplace(&mut output, &encoded.0);
                scutils::xor_inplace(&mut output, &seeds[nbins + i].0);
                writer.write_all(&output)?;
            }
            // eprintln!("[S] Send set: {} ms", start.elapsed().unwrap().as_millis());
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
        let n = inputs.len();

        let key = rand::random::<Block>();
        let aes = Aes128::new(key);
        let inputs_ = compress_and_hash_inputs(inputs, &aes);
        let tbl = CuckooHash::build(&inputs_)?;
        let nbins = tbl.nbins;
        let stashsize = tbl.stashsize;
        let masksize = compute_masksize(n)?;
        let hindices = (0..NHASHES)
            .map(|i| Block::from(i as u128))
            .collect::<Vec<Block>>();
        // Send cuckoo hash info to sender.
        key.write(writer)?;
        stream::write_usize(writer, nbins)?;
        stream::write_usize(writer, stashsize)?;
        writer.flush()?;
        // Set up inputs to use `x || i` or `x` depending on whether the input
        // is in a bin or the stash.
        let inputs_ = tbl
            .items()
            .filter_map(|(item, _, hidx)| {
                if let Some(item) = item {
                    if let Some(hidx) = hidx {
                        // Item in bin.
                        Some(*item ^ hindices[*hidx])
                    } else {
                        // Item in stash.
                        Some(*item)
                    }
                } else {
                    Some(Default::default())
                }
            })
            .collect::<Vec<Block>>();
        let outputs = self.oprf.receive(reader, writer, &inputs_, rng)?;
        // Receive all the sets from the sender.
        // let start = SystemTime::now();
        let mut hs = (0..NHASHES)
            .map(|_| HashSet::with_capacity(n))
            .collect::<Vec<HashSet<Vec<u8>>>>();
        let mut ss = (0..stashsize)
            .map(|_| HashSet::with_capacity(n))
            .collect::<Vec<HashSet<Vec<u8>>>>();
        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                reader.read_exact(&mut buf)?;
                h.insert(buf);
            }
        }
        for s in ss.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                reader.read_exact(&mut buf)?;
                s.insert(buf);
            }
        }
        // println!(
        //     "[R] Receive sets: {} ms",
        //     start.elapsed().unwrap().as_millis()
        // );
        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        // let start = SystemTime::now();
        let mut intersection = Vec::with_capacity(n);
        for (i, (&item, output_)) in tbl.items().zip(outputs.into_iter()).enumerate() {
            let (_, idx, hidx) = item;
            let mut output = vec![0u8; masksize];
            output.copy_from_slice(&output_.0[0..masksize]);
            if let Some(hidx) = hidx {
                // We have a bin item.
                if hs[hidx].contains(&output) {
                    intersection.push(inputs[idx.unwrap()].clone());
                }
            } else if let Some(idx) = idx {
                // We have a stash item.
                let j = i - nbins;
                if ss[j].contains(&output) {
                    intersection.push(inputs[idx].clone());
                }
            }
        }
        // println!(
        //     "[R] Compute intersection: {} ms",
        //     start.elapsed().unwrap().as_millis()
        // );
        Ok(intersection)
    }
}

// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
// as zero. We need to leave 8 bits free in order to add in the hash index when
// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
fn compress_and_hash_inputs(inputs: &[Vec<u8>], aes: &Aes128) -> Vec<Block> {
    let mut compressed = Vec::with_capacity(inputs.len());
    for input in inputs.iter() {
        let mut digest = [0u8; 16];
        if input.len() < 16 {
            // Map `input` directly to a `Block`
            for (byte, result) in input.iter().zip(digest.iter_mut()) {
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
        let digest = aes.encrypt(Block::from(digest));
        compressed.push(digest);
    }
    compressed
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
    use std::time::SystemTime;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 16;

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
            let start = SystemTime::now();
            psi.send(&mut reader, &mut writer, &sender_inputs, &mut rng)
                .unwrap();
            println!(
                "[{}] Sender time: {} ms",
                NTIMES,
                start.elapsed().unwrap().as_millis()
            );
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut psi = PszReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let start = SystemTime::now();
        let intersection = psi
            .receive(&mut reader, &mut writer, &receiver_inputs, &mut rng)
            .unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            NTIMES,
            start.elapsed().unwrap().as_millis()
        );
        handle.join().unwrap();
        assert_eq!(intersection.len(), NTIMES);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 16;

    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
        (0..size).map(|_| rand_vec(SIZE)).collect()
    }

    #[bench]
    fn bench_compress_inputs(b: &mut Bencher) {
        let inputs = rand_vec_vec(NTIMES);
        let key = rand::random::<Block>();
        let aes = Aes128::new(key);
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, &aes);
        });
    }
}
