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
use itertools::Itertools;
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{cointoss, AbstractChannel, Block, Block512, SemiHonest};
use std::collections::{HashMap, HashSet};

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
        inputs: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let key = cointoss::send(channel, &[rng.gen()])?[0];
        let inputs = utils::compress_and_hash_inputs(inputs, key);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = channel.read_usize()?;
        let seeds = self.oprf.send(channel, nbins, rng)?;

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Block512::default();
        let mut indices = (0..inputs.len()).collect_vec();
        for i in 0..NHASHES {
            // shuffle the indices in order to send out of order
            indices.shuffle(rng);

            let hidx = Block::from(i as u128);
            for &j in &indices {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(inputs[j], i, nbins);

                // Compute `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(inputs[j] ^ hidx, &mut encoded);
                encoded ^= seeds[bin];

                channel.write_bytes(&encoded.prefix(masksize))?;
            }
        }
        channel.flush()?;
        Ok(())
    }

    /// Run the PSI protocol over `inputs`. Returns a random key for each input which can
    /// be used to encrypt payloads.
    pub fn send_payloads<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let key = cointoss::send(channel, &[rng.gen()])?[0];
        let masksize = compute_masksize(inputs.len())?;
        let inputs = utils::compress_and_hash_inputs(inputs, key);
        let nbins = channel.read_usize()?;
        let seeds = self.oprf.send(channel, nbins, rng)?;
        let payloads = (0..inputs.len()).map(|_| rng.gen::<Block>()).collect_vec();

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Block512::default();
        let mut indices = (0..inputs.len()).collect_vec();
        for i in 0..NHASHES {
            // shuffle the indices in order to send out of order
            indices.shuffle(rng);

            let hidx = Block::from(i as u128);
            for &j in &indices {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(inputs[j], i, nbins);

                // Compute `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(inputs[j] ^ hidx, &mut encoded);
                encoded ^= seeds[bin];

                let tag = &encoded.as_ref()[0..masksize];
                let key = &encoded.as_ref()[masksize..masksize+16];

                // encrypt payload
                let mut ct = payloads[j].clone();
                scuttlebutt::utils::xor_inplace(ct.as_mut(), key);

                channel.write_bytes(&tag[0..masksize])?;
                channel.write_bytes(ct.as_ref())?;
            }
        }
        channel.flush()?;
        Ok(payloads)
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
        inputs: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let n = inputs.len();
        let masksize = compute_masksize(n)?;

        let (tbl, outputs) = self.perform_oprfs(inputs, channel, rng)?;

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
                    let val = inputs[item.input_index].clone();
                    intersection.push(val);
                }
            }
        }

        Ok(intersection)
    }

    /// Run the PSI protocol over `inputs`, receiving a vector of tuples consisting of
    /// the intersection items and associated payloads.
    pub fn receive_payloads<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        Vec<(
            Vec<u8>, // Intersection item
            Block, // Payload
        )>,
        Error,
    > {
        let (tbl, outputs) = self.perform_oprfs(inputs, channel, rng)?;
        let n = inputs.len();
        let masksize = compute_masksize(n)?;

        // Receive all the sets from the sender. These come in paired with H(F(x)), which
        // allows tree searching without learning the Sender's F(x) values (which are used
        // to encrypt the payloads).
        let mut hs = vec![HashMap::with_capacity(n); NHASHES];
        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut tag = vec![0; masksize];
                channel.read_bytes(&mut tag)?;
                let ct = channel.read_block()?;
                h.insert(tag, ct);
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);

        for (opt_item, output) in tbl.items.iter().zip(outputs.into_iter()) {
            if let Some(item) = opt_item {
                let tag = &output.as_ref()[0..masksize];

                // if the tag is present, decrypt the payload using F(x).
                if let Some(ct) = hs[item.hash_index].get(tag) {
                    let val = inputs[item.input_index].clone();
                    let key = &output.as_ref()[masksize..masksize+16];
                    let payload_bytes = scuttlebutt::utils::xor(ct.as_ref(), key);
                    let payload = Block::try_from_slice(&payload_bytes).expect("it is exactly 16 bytes long");
                    intersection.push((val, payload));
                }
            }
        }

        Ok(intersection)
    }

    // Helper to do computation common to both receive and receive_payloads
    fn perform_oprfs<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        (
            CuckooHash,    // Cuckoo Table
            Vec<Block512>, // OPRF outputs
        ),
        Error,
    > {
        let key = cointoss::receive(channel, &[rng.gen()])?[0];

        let tbl = CuckooHash::new(&utils::compress_and_hash_inputs(inputs, key), NHASHES)?;
        let nbins = tbl.nbins;

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

        let oprf_outputs = self.oprf.receive(channel, &oprf_inputs, rng)?;

        Ok((tbl, oprf_outputs))
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;
    use rand::Rng;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Channel};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{BufReader, BufWriter};
    use std::iter::FromIterator;
    use std::os::unix::net::UnixStream;

    const ITEM_SIZE: usize = 16;
    const SET_SIZE: usize = 1 << 4;

    #[test]
    fn test_psi_complete_intersection() {
        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        let intersection = psi
            .receive(&receiver_inputs, &mut channel, &mut rng)
            .unwrap();
        handle.join().unwrap();
        assert_eq!(intersection.len(), SET_SIZE);
    }

    #[test]
    fn test_payloads() {
        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            psi.send_payloads(&sender_inputs, &mut channel, &mut rng)
                .unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        let payloads = psi
            .receive_payloads(&receiver_inputs, &mut channel, &mut rng)
            .unwrap();
        handle.join().unwrap();

        assert_eq!(payloads.len(), SET_SIZE);
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum Where {
        Sender,
        Receiver,
        Both,
    }

    impl Arbitrary for Where {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            match g.gen_range(0, 3) {
                0 => Where::Sender,
                1 => Where::Receiver,
                2 => Where::Both,
                _ => panic!("out of range"),
            }
        }
    }

    #[quickcheck]
    fn test_psi_incomplete_intersection(items: BTreeMap<u32, Where>) -> TestResult {
        if items.is_empty() {
            return TestResult::discard();
        }
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut sender_inputs = Vec::new();
        let mut receiver_inputs = Vec::new();
        let mut expected_intersection: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (x, w) in items.into_iter() {
            let v = x.to_le_bytes().to_vec();
            if w == Where::Both || w == Where::Sender {
                sender_inputs.push(v.clone());
            }
            if w == Where::Both || w == Where::Receiver {
                receiver_inputs.push(v.clone());
            }
            if w == Where::Both {
                expected_intersection.insert(v);
            }
        }
        if sender_inputs.is_empty() || receiver_inputs.is_empty() {
            return TestResult::discard();
        }
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed((0 as u128).into());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
        });
        let mut rng = AesRng::from_seed((1 as u128).into());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        let intersection = psi
            .receive(&receiver_inputs, &mut channel, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let actual_intersection: BTreeSet<Vec<u8>> = BTreeSet::from_iter(intersection.into_iter());
        assert_eq!(actual_intersection, expected_intersection);
        TestResult::from_bool(true)
    }
}
