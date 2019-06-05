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
use crate::{utils, Error};
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::utils as scutils;
use scuttlebutt::{cointoss, AbstractChannel, Block, Block512, SemiHonest};
use std::collections::HashSet;

const NHASHES: usize = 3;

/// Private set intersection sender.
pub struct Sender {
    oprf: oprf::KkrtSender,
}
/// Private set intersection receiver.
pub struct Receiver {
    oprf: oprf::KkrtReceiver,
}

impl Sender {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtSender::init(channel, rng)?;
        Ok(Self { oprf })
    }

    pub fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        let keys = cointoss::send(channel, &[rng.gen()])?;
        let mut inputs = utils::compress_and_hash_inputs(inputs, keys[0]);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = channel.read_usize()?;
        let stashsize = channel.read_usize()?;
        let seeds = self.oprf.send(channel, nbins + stashsize, rng)?;

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Default::default();
        for i in 0..NHASHES {
            inputs.shuffle(&mut rng);
            let hidx = Block::from(i as u128);
            for input in &inputs {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(*input, i, nbins);
                // Compute `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(*input ^ hidx, &mut encoded);
                scutils::xor_inplace_n(
                    &mut encoded.prefix_mut(masksize),
                    &seeds[bin].prefix(masksize),
                    masksize,
                );
                channel.write_bytes(&encoded.prefix(masksize))?;
            }
            channel.flush()?;
        }
        if stashsize > 0 {
            // For each `i ∈ {1, ..., stashsize}`, construct set `Sᵢ =
            // {F(k_{nbins+i}, x) | x ∈ X}`, randomly permute it, and send it to the
            // receiver.
            let mut encoded = inputs
                .iter()
                .map(|input| {
                    let mut out = Default::default();
                    self.oprf.encode(*input, &mut out);
                    out
                })
                .collect::<Vec<Block512>>();
            for i in 0..stashsize {
                encoded.shuffle(&mut rng);
                for encoded in &encoded {
                    // We don't need to append any hash index to OPRF inputs in the stash.
                    let mut output = vec![0u8; masksize];
                    scutils::xor_inplace(&mut output, &encoded.prefix(masksize));
                    scutils::xor_inplace(&mut output, &seeds[nbins + i].prefix(masksize));
                    channel.write_bytes(&output)?;
                }
            }
            channel.flush()?;
        }
        Ok(())
    }
}

impl Receiver {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtReceiver::init(channel, rng)?;
        Ok(Self { oprf })
    }

    pub fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let n = inputs.len();

        let keys = cointoss::receive(channel, &[rng.gen()])?;
        let inputs_ = utils::compress_and_hash_inputs(inputs, keys[0]);

        let tbl = CuckooHash::new(&inputs_, NHASHES)?;

        let nbins = tbl.nbins;
        let stashsize = tbl.stashsize;
        let masksize = compute_masksize(n)?;

        let hindices = (0..NHASHES)
            .map(|i| Block::from(i as u128))
            .collect::<Vec<Block>>();

        // Send cuckoo hash info to sender.
        channel.write_usize(nbins)?;
        channel.write_usize(stashsize)?;
        channel.flush()?;

        // Set up inputs to use `x || i` or `x` depending on whether the input
        // is in a bin or the stash.
        let inputs_ = tbl
            .items()
            .map(|opt_item| {
                if let Some(item) = opt_item {
                    if let Some(hidx) = item.hash_index {
                        // Item in bin. In this case, set the last byte to the
                        // hash index.
                        item.entry ^ hindices[hidx]
                    } else {
                        // Item in stash. No need to add the hash index in this
                        // case.
                        item.entry
                    }
                } else {
                    // No item found, so use the "default" item.
                    Default::default()
                }
            })
            .collect::<Vec<Block>>();
        assert_eq!(inputs_.len(), nbins + stashsize);

        let outputs = self.oprf.receive(channel, &inputs_, rng)?;

        // Receive all the sets from the sender.
        let mut hs = (0..NHASHES)
            .map(|_| HashSet::with_capacity(n))
            .collect::<Vec<HashSet<Vec<u8>>>>();

        let mut ss = (0..stashsize)
            .map(|_| HashSet::with_capacity(n))
            .collect::<Vec<HashSet<Vec<u8>>>>();

        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                channel.read_bytes(&mut buf)?;
                h.insert(buf);
            }
        }

        for s in ss.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0u8; masksize];
                channel.read_bytes(&mut buf)?;
                s.insert(buf);
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);
        for (i, (opt_item, output)) in tbl.items().zip(outputs.into_iter()).enumerate() {
            if let Some(item) = opt_item {
                let prefix = output.prefix(masksize);
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
    use scuttlebutt::{AesRng, Channel};
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
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let start = SystemTime::now();
            let mut psi = PszSender::init(&mut channel, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
            println!(
                "[{}] Send time: {} ms",
                NTIMES,
                start.elapsed().unwrap().as_millis()
            );
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let start = SystemTime::now();
        let mut psi = PszReceiver::init(&mut channel, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let intersection = psi
            .receive(&mut channel, &receiver_inputs, &mut rng)
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
