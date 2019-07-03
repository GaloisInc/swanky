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
use scuttlebutt::{Block512, cointoss, AbstractChannel, Block, SemiHonest};
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
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtSender::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let key = cointoss::send(channel, &[rng.gen()])?[0];
        let mut inputs = utils::compress_and_hash_inputs(inputs, key);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = channel.read_usize()?;
        let seeds = self.oprf.send(channel, nbins, rng)?;

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Block512::default();
        for i in 0..NHASHES {
            inputs.shuffle(rng);
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
        }
        channel.flush()?;
        Ok(())
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let oprf = oprf::KkrtReceiver::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let n = inputs.len();
        let key = cointoss::receive(channel, &[rng.gen()])?[0];

        let tbl = CuckooHash::new(&utils::compress_and_hash_inputs(inputs, key), NHASHES)?;
        let nbins = tbl.nbins;
        let masksize = compute_masksize(n)?;

        // Send cuckoo hash info to sender.
        channel.write_usize(nbins)?;
        channel.flush()?;

        // Extract inputs from cuckoo hash.
        let oprf_inputs = tbl
            .items
            .iter()
            .map(|opt_item| {
                if let Some(item) = opt_item {
                    item.entry
                } else {
                    // No item found, so use the "default" item.
                    Block::default()
                }
            })
            .collect::<Vec<Block>>();

        let outputs = self.oprf.receive(channel, &oprf_inputs, rng)?;

        // Receive all the sets from the sender.
        let mut hs = vec![HashSet::with_capacity(n); NHASHES];
        for h in hs.iter_mut() {
            for _ in 0..n {
                let buf = channel.read_vec(masksize)?;
                h.insert(buf);
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);
        for (opt_item, output) in tbl.items.iter().zip(outputs.into_iter()) {
            if let Some(item) = opt_item {
                let prefix = output.prefix(masksize);
                if hs[item.hash_index].contains(prefix) {
                    intersection.push(inputs[item.input_index].clone());
                }
            }
        }
        Ok(intersection)
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const SIZE: usize = 16;
    const NTIMES: usize = 1 << 4;

    #[test]
    fn test_psi() {
        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(NTIMES, SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        let intersection = psi
            .receive(&mut channel, &receiver_inputs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        assert_eq!(intersection.len(), NTIMES);
    }
}
