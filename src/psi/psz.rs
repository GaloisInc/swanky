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
use digest::Digest;
use itertools::Itertools;
use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{cointoss, AbstractChannel, Block, Block512, SemiHonest};
use sha2::Sha256;
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
        channel: &mut C,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        self.send_payloads(channel, inputs, &[], rng)
    }

    /// Run the PSI protocol over `inputs` with payloads.
    pub fn send_payloads<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
        payloads: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // send the length of the payloads
        let payload_len = payloads.first().map_or(0, Vec::len);
        if payload_len > 0 {
            assert!(payloads.iter().all(|p| p.len() == payload_len));
            assert_eq!(payloads.len(), inputs.len());
            channel.write_usize(payload_len)?;
        }

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

                // If payloads are not present, use the original protocol.
                // Otherwise, use the new protocol and send payloads encrypted under
                // F(...), tagged by H(F(...)).
                if payload_len == 0 {
                    channel.write_bytes(&encoded.prefix(masksize))?;
                } else {
                    // compute and send tag
                    let tag: [u8; 32] = Sha256::digest(encoded.prefix(masksize)).into();

                    // encrypt payload
                    let iv: [u8; 16] = rng.gen();
                    let key = encoded.prefix(16);
                    let ct = openssl::symm::encrypt(
                        openssl::symm::Cipher::aes_128_ctr(),
                        &key,
                        Some(&iv),
                        &payloads[j],
                    )?;

                    channel.write_bytes(&tag)?;
                    channel.write_bytes(&iv)?;
                    channel.write_bytes(&ct)?;
                }
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
        let masksize = compute_masksize(n)?;

        let (tbl, outputs) = self.perform_oprfs(channel, inputs, rng)?;

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
        channel: &mut C,
        inputs: &[Vec<u8>],
        rng: &mut RNG,
    ) -> Result<
        Vec<(
            Vec<u8>, // Intersection item
            Vec<u8>, // Payload
        )>,
        Error,
    > {
        let payload_len = channel.read_usize()?;
        let (tbl, outputs) = self.perform_oprfs(channel, inputs, rng)?;
        let n = inputs.len();
        let masksize = compute_masksize(n)?;

        // Receive all the sets from the sender. These come in paired with H(F(x)), which
        // allows tree searching without learning the Sender's F(x) values (which are used
        // to encrypt the payloads).
        let mut hs = vec![HashMap::with_capacity(n); NHASHES];
        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut tag = [0_u8; 32];
                let mut iv = [0_u8; 16];
                channel.read_bytes(&mut tag)?;
                channel.read_bytes(&mut iv)?;
                let ct = channel.read_vec(payload_len)?;
                h.insert(tag, (iv, ct));
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);

        for (opt_item, output) in tbl.items.iter().zip(outputs.into_iter()) {
            if let Some(item) = opt_item {
                // compute tag = H(F(x))
                let tag: [u8; 32] = Sha256::digest(output.prefix(masksize)).into();

                // if the tag is present, decrypt the payload using F(x).
                if let Some((iv, ct)) = hs[item.hash_index].get(&tag) {
                    let val = inputs[item.input_index].clone();
                    let payload = openssl::symm::decrypt(
                        openssl::symm::Cipher::aes_128_ctr(),
                        output.prefix(16),
                        Some(iv),
                        ct,
                    )?;
                    intersection.push((val, payload));
                }
            }
        }

        Ok(intersection)
    }

    // Helper to do computation common to both receive and receive_payloads
    fn perform_oprfs<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        inputs: &[Vec<u8>],
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
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const ITEM_SIZE: usize = 16;
    const SET_SIZE: usize = 1 << 4;

    #[test]
    fn test_psi() {
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
        assert_eq!(intersection.len(), SET_SIZE);
    }

    #[test]
    fn test_payloads() {
        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        let payloads = rand_vec_vec(SET_SIZE, 32, &mut rng);

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            psi.send_payloads(&mut channel, &sender_inputs, &payloads, &mut rng)
                .unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        let payloads = psi
            .receive_payloads(&mut channel, &receiver_inputs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        assert_eq!(payloads.len(), SET_SIZE);
    }
}
