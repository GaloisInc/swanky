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
use ocelot::oprf::kkrt::Output;
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use scuttlebutt::utils as scutils;
use scuttlebutt::{AesHash, Block, SemiHonest};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::time::SystemTime;

/// Private set intersection sender.
pub struct PszPsiSender {
    oprf: oprf::KkrtSender,
}
/// Private set intersection receiver.
pub struct PszPsiReceiver {
    oprf: oprf::KkrtReceiver,
}

impl PrivateSetIntersectionSender for PszPsiSender {
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtSender::init(reader, writer, rng)?;
        Ok(Self { oprf })
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Self::Msg],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        // XXX: do we need to do cointossing here?
        let total = SystemTime::now();
        let key = Block::read(reader)?;
        let mut inputs = compress_and_hash_inputs(inputs, key);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        let start = SystemTime::now();
        let seeds = self.oprf.send(reader, writer, nbins + stashsize, rng)?;
        println!("[S] OPRF send: {} ms", start.elapsed().unwrap().as_millis());
        // For each `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x || i) | x ∈ X)}`,
        // randomly permute it, and send it to the receiver.
        let start = SystemTime::now();
        let mut encoded = Output([0u8; 64]);
        for i in 0..NHASHES {
            inputs.shuffle(&mut rng);
            let hidx = Block::from(i as u128);
            for input in &inputs {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(*input, i, nbins);
                // Compute rest of `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(*input ^ hidx, &mut encoded);
                scutils::xor_inplace_n(&mut encoded.0, &seeds[bin].0, masksize);
                writer.write_all(&encoded.0[0..masksize])?;
            }
        }
        // For each `i ∈ {1, ..., stashsize}`, construct set `Sᵢ =
        // {F(k_{nbins+i}, x) | x ∈ X}`, randomly permute it, and send it to the
        // receiver.
        let mut encoded = inputs
            .iter()
            .map(|input| {
                let mut out = Output([0u8; 64]);
                self.oprf.encode(*input, &mut out);
                out
            })
            .collect::<Vec<Output>>();
        for i in 0..stashsize {
            encoded.shuffle(&mut rng);
            for encoded in &encoded {
                // We don't need to append any hash index to OPRF inputs in the stash.
                let mut output = vec![0u8; masksize];
                scutils::xor_inplace(&mut output, &encoded.0);
                scutils::xor_inplace(&mut output, &seeds[nbins + i].0);
                writer.write_all(&output)?;
            }
        }
        println!("[S] Send sets: {} ms", start.elapsed().unwrap().as_millis());
        writer.flush()?;
        println!("[S] Total: {} ms", total.elapsed().unwrap().as_millis());
        Ok(())
    }
}

impl PrivateSetIntersectionReceiver for PszPsiReceiver {
    type Msg = Vec<u8>;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtReceiver::init(reader, writer, rng)?;
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
        let inputs_ = compress_and_hash_inputs(inputs, key);
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
                        // Item in bin. In this case, set the last byte to the
                        // hash index.
                        Some(*item ^ hindices[*hidx])
                    } else {
                        // Item in stash. No need to add the hash index in this
                        // case.
                        Some(*item)
                    }
                } else {
                    // No item found, so use the "default" item.
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
        let start = SystemTime::now();
        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                reader.read_exact(&mut buf)?;
                h.insert(buf);
            }
        }
        println!(
            "[R] Inserts to hash set: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        for s in ss.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                reader.read_exact(&mut buf)?;
                s.insert(buf);
            }
        }
        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);
        for (i, (&item, output_)) in tbl.items().zip(outputs.into_iter()).enumerate() {
            let (_, idx, hidx) = item;
            if let Some(hidx) = hidx {
                // We have a bin item.
                if hs[hidx].contains(&output_.0[0..masksize]) {
                    intersection.push(inputs[idx.unwrap()].clone());
                }
            } else if let Some(idx) = idx {
                // We have a stash item.
                let j = i - nbins;
                if ss[j].contains(&output_.0[0..masksize]) {
                    intersection.push(inputs[idx].clone());
                }
            }
        }
        Ok(intersection)
    }
}

// Compress an arbitrary vector into a 128-bit chunk, leaving the final 8-bits
// as zero. We need to leave 8 bits free in order to add in the hash index when
// running the OPRF (cf. <https://eprint.iacr.org/2016/799>, §5.2).
fn compress_and_hash_inputs(inputs: &[Vec<u8>], key: Block) -> Vec<Block> {
    let mut hasher = Sha256::new(); // XXX can we do better than using SHA-256?
    let aes = AesHash::new(key);
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut digest = [0u8; 16];
            if input.len() < 16 {
                // Map `input` directly to a `Block`.
                digest[0..input.len()].copy_from_slice(input);
            } else {
                // Hash `input` first.
                hasher.input(input);
                let h = hasher.result_reset();
                digest[0..15].copy_from_slice(&h[0..15]);
            }
            aes.cr_hash(Block::from(i as u128), Block::from(digest))
        })
        .collect::<Vec<Block>>()
}

impl SemiHonest for PszPsiSender {}
impl SemiHonest for PszPsiReceiver {}

/// Private set intersection sender using the KKRT oblivious PRF under-the-hood.
pub type PszSender = PszPsiSender;
/// Private set intersection receiver using the KKRT oblivious PRF
/// under-the-hood.
pub type PszReceiver = PszPsiReceiver;

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::time::SystemTime;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 18;

    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
        (0..size).map(|_| rand_vec(SIZE)).collect()
    }

    #[test]
    fn test_compress_and_hash_inputs() {
        let key = rand::random::<Block>();
        let inputs = rand_vec_vec(13);
        let _ = compress_and_hash_inputs(&inputs, key);
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
            let start = SystemTime::now();
            let mut psi = PszSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            psi.send(&mut reader, &mut writer, &sender_inputs, &mut rng)
                .unwrap();
            println!(
                "[{}] Send time: {} ms",
                NTIMES,
                start.elapsed().unwrap().as_millis()
            );
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let start = SystemTime::now();
        let mut psi = PszReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
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

    const NTIMES: usize = 1 << 16;

    fn rand_vec(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    fn rand_vec_vec(n: usize, size: usize) -> Vec<Vec<u8>> {
        (0..n).map(|_| rand_vec(size)).collect()
    }

    #[bench]
    fn bench_compress_and_hash_inputs_small(b: &mut Bencher) {
        let inputs = rand_vec_vec(NTIMES, 15);
        let key = rand::random::<Block>();
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }

    #[bench]
    fn bench_compress_and_hash_inputs_large(b: &mut Bencher) {
        let inputs = rand_vec_vec(NTIMES, 32);
        let key = rand::random::<Block>();
        b.iter(|| {
            let _ = compress_and_hash_inputs(&inputs, key);
        });
    }

}
