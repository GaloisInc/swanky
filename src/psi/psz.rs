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

use crate::cuckoo::{compute_masksize, CuckooHash};
use crate::stream;
use crate::utils;
use crate::Error;
use crate::{Receiver as PsiReceiver, Sender as PsiSender};
use ocelot::oprf::kkrt::Output;
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
use rand::seq::SliceRandom;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use scuttlebutt::utils as scutils;
use scuttlebutt::{Block, SemiHonest};
use std::collections::HashSet;
use std::io::{Read, Write};

const NHASHES: usize = 3;

/// Private set intersection sender.
pub struct Sender {
    oprf: oprf::KkrtSender,
}
/// Private set intersection receiver.
pub struct Receiver {
    oprf: oprf::KkrtReceiver,
}

impl PsiSender for Sender {
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
        let key = Block::read(reader)?;
        let mut inputs = utils::compress_and_hash_inputs(inputs, key);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = stream::read_usize(reader)?;
        let stashsize = stream::read_usize(reader)?;
        let seeds = self.oprf.send(reader, writer, nbins + stashsize, rng)?;

        // For each `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x || i) | x ∈ X)}`,
        // randomly permute it, and send it to the receiver.
        let mut encoded = Output::zero();
        for i in 0..NHASHES {
            inputs.shuffle(&mut rng);
            let hidx = Block::from(i as u128);
            for input in &inputs {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(*input, i, nbins);
                // Compute rest of `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(*input ^ hidx, &mut encoded);
                scutils::xor_inplace_n(
                    &mut encoded.prefix_mut(masksize),
                    &seeds[bin].prefix(masksize),
                    masksize,
                );
                writer.write_all(&encoded.prefix(masksize))?;
            }
        }

        // For each `i ∈ {1, ..., stashsize}`, construct set `Sᵢ =
        // {F(k_{nbins+i}, x) | x ∈ X}`, randomly permute it, and send it to the
        // receiver.
        let mut encoded = inputs
            .iter()
            .map(|input| {
                let mut out = Output::zero();
                self.oprf.encode(*input, &mut out);
                out
            })
            .collect::<Vec<Output>>();

        for i in 0..stashsize {
            encoded.shuffle(&mut rng);
            for encoded in &encoded {
                // We don't need to append any hash index to OPRF inputs in the stash.
                let mut output = vec![0u8; masksize];
                scutils::xor_inplace(&mut output, &encoded.prefix(masksize));
                scutils::xor_inplace(&mut output, &seeds[nbins + i].prefix(masksize));
                writer.write_all(&output)?;
            }
        }

        writer.flush()?;
        Ok(())
    }
}

impl PsiReceiver for Receiver {
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

        let key = rng.gen();
        let inputs_ = utils::compress_and_hash_inputs(inputs, key);

        let tbl = CuckooHash::new(&inputs_, NHASHES)?;

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
            .filter_map(|opt_item| {
                if let Some(item) = opt_item {
                    if let Some(hidx) = item.hash_index {
                        // Item in bin. In this case, set the last byte to the
                        // hash index.
                        Some(item.entry ^ hindices[hidx])
                    } else {
                        // Item in stash. No need to add the hash index in this
                        // case.
                        Some(item.entry)
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

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);
        for (i, (opt_item, output_)) in tbl.items().zip(outputs.into_iter()).enumerate() {
            if let Some(item) = opt_item {
                let prefix = output_.prefix(masksize);
                if let Some(hidx) = item.hash_index {
                    // We have a bin item.
                    if hs[hidx].contains(prefix) {
                        intersection.push(inputs[item.input_index].clone());
                    }
                } else {
                    // We have a stash item.
                    let j = i - nbins;
                    if ss[j].contains(prefix) {
                        intersection.push(inputs[item.input_index].clone());
                    }
                }
            }
        }
        Ok(intersection)
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

/// Private set intersection sender using the KKRT oblivious PRF under-the-hood.
pub type PszSender = Sender;
/// Private set intersection receiver using the KKRT oblivious PRF
/// under-the-hood.
pub type PszReceiver = Receiver;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::time::SystemTime;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 10;

    #[test]
    fn test_psi() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(NTIMES, SIZE);
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
