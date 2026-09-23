//! Implementation of the Pinkas-Schneider-Zohner private set intersection
//! protocol (cf. <https://eprint.iacr.org/2014/447>) as specified by
//! Kolesnikov-Kumaresan-Rosulek-Trieu (cf. <https://eprint.iacr.org/2016/799>).
//!
//! The current implementation does not hash the output of the (relaxed) OPRF.

use crate::{
    cuckoo::{CuckooHash, compute_masksize},
    utils,
};
use itertools::Itertools;
use rand::{CryptoRng, RngExt, seq::SliceRandom};
use std::collections::{HashMap, HashSet};
use swanky_adversary::SemiHonest;
use swanky_block::{Block, Block512};
use swanky_channel::Channel;
use swanky_cointoss;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_oprf_traits::{Receiver as OprfReceiver, Sender as OprfSender};

const NHASHES: usize = 3;

/// Private set intersection sender.
pub struct Sender {
    oprf: swanky_oprf_kkrt::Sender,
}
/// Private set intersection receiver.
pub struct Receiver {
    oprf: swanky_oprf_kkrt::Receiver,
}

impl Sender {
    /// Initialize the PSI sender.
    pub fn init<RNG: CryptoRng>(channel: &mut Channel, rng: &mut RNG) -> Result<Self> {
        let oprf = swanky_oprf_kkrt::Sender::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<RNG: CryptoRng>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<()> {
        let key = swanky_cointoss::send(channel, &[rng.random()])
            .wrap_err(ErrorKind::OtherError, "Cointoss protocol failed")?[0];
        let inputs = utils::compress_and_hash_inputs(inputs, key);
        let masksize = compute_masksize(inputs.len())?;
        let nbins = channel.read()?;
        let seeds = self.oprf.send(channel, nbins, rng)?;

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Block512::default();
        let mut indices = (0..inputs.len()).collect_vec();
        for i in 0..NHASHES {
            // shuffle the indices in order to send out of order
            indices.shuffle(rng);

            for &j in &indices {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(inputs[j], i, nbins);

                // Compute `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(inputs[j], &mut encoded);
                encoded ^= seeds[bin];

                channel
                    .write_bytes(encoded.prefix(masksize))
                    .wrap_err(ErrorKind::NetworkError, "Failed to write bytes")?;
            }
        }
        Ok(())
    }

    /// Run the PSI protocol over `inputs`. Returns a random key for each input which can
    /// be used to encrypt payloads.
    pub fn send_payloads<RNG: CryptoRng>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<Vec<Block>> {
        let key = swanky_cointoss::send(channel, &[rng.random()])
            .wrap_err(ErrorKind::OtherError, "Cointoss protocol failed")?[0];
        let masksize = compute_masksize(inputs.len())?;
        let inputs = utils::compress_and_hash_inputs(inputs, key);
        let nbins = channel.read()?;
        let seeds = self.oprf.send(channel, nbins, rng)?;
        let payloads = (0..inputs.len())
            .map(|_| rng.random::<Block>())
            .collect_vec();

        // For each hash function `hᵢ`, construct set `Hᵢ = {F(k_{hᵢ(x)}, x ||
        // i) | x ∈ X)}`, randomly permute it, and send it to the receiver.
        let mut encoded = Block512::default();
        let mut indices = (0..inputs.len()).collect_vec();
        for i in 0..NHASHES {
            // shuffle the indices in order to send out of order
            indices.shuffle(rng);

            for &j in &indices {
                // Compute `bin := hᵢ(x)`.
                let bin = CuckooHash::bin(inputs[j], i, nbins);

                // Compute `F(k_{hᵢ(x)}, x || i)` and chop off extra bytes.
                self.oprf.encode(inputs[j], &mut encoded);
                encoded ^= seeds[bin];

                let tag = &encoded.as_ref()[0..masksize];
                let key = &encoded.as_ref()[masksize..masksize + 16];

                // encrypt payload
                let mut ct = payloads[j];
                ct.as_mut()
                    .iter_mut()
                    .zip(key.iter())
                    .for_each(|(a, &b)| *a ^= b);

                channel
                    .write_bytes(&tag[0..masksize])
                    .wrap_err(ErrorKind::NetworkError, "Failedd to write bytes")?;
                channel
                    .write_bytes(ct.as_ref())
                    .wrap_err(ErrorKind::NetworkError, "Failed to write bytes")?;
            }
        }
        Ok(payloads)
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<RNG: CryptoRng>(channel: &mut Channel, rng: &mut RNG) -> Result<Self> {
        let oprf = swanky_oprf_kkrt::Receiver::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn receive<RNG: CryptoRng>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<Vec<Vec<u8>>> {
        let n = inputs.len();
        let masksize = compute_masksize(n)?;

        let (tbl, outputs) = self.perform_oprfs(inputs, channel, rng)?;

        // Receive all the sets from the sender.
        let mut hs = vec![HashSet::with_capacity(n); NHASHES];
        for h in hs.iter_mut() {
            for _ in 0..n {
                let mut buf = vec![0; masksize];
                channel.read_bytes(&mut buf)?;
                h.insert(buf);
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = Vec::with_capacity(n);
        for (opt_item, output) in tbl.items.iter().zip(outputs) {
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
    pub fn receive_payloads<RNG: CryptoRng>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<
        HashMap<
            Vec<u8>, // Intersection item
            Block,   // Payload
        >,
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
                channel
                    .read_bytes(&mut tag)
                    .wrap_err(ErrorKind::NetworkError, "Failed to read bytes")?;
                let ct = channel.read::<Block>()?;
                h.insert(tag, ct);
            }
        }

        // Iterate through each input/output pair and see whether it exists in
        // the appropriate set.
        let mut intersection = HashMap::with_capacity(n);

        for (opt_item, output) in tbl.items.iter().zip(outputs) {
            if let Some(item) = opt_item {
                let tag = &output.as_ref()[0..masksize];

                // if the tag is present, decrypt the payload using F(x).
                if let Some(&ct) = hs[item.hash_index].get(tag) {
                    let val = inputs[item.input_index].clone();
                    let key = Block::from(
                        <[u8; 16]>::try_from(&output.as_ref()[masksize..masksize + 16])
                            .expect("it is exactly 16 bytes long"),
                    );
                    let payload = ct ^ key;
                    intersection.insert(val, payload);
                }
            }
        }

        Ok(intersection)
    }

    // Helper to do computation common to both receive and receive_payloads
    fn perform_oprfs<RNG: CryptoRng>(
        &mut self,
        inputs: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<(
        CuckooHash,    // Cuckoo Table
        Vec<Block512>, // OPRF outputs
    )> {
        let key = swanky_cointoss::receive(channel, &[rng.random()])
            .wrap_err(ErrorKind::OtherError, "Cointoss protocol failed")?[0];

        let hashed = utils::compress_and_hash_inputs(inputs, key);

        let tbl = CuckooHash::new(&hashed, NHASHES)?;
        let nbins = tbl.nbins;

        // Send cuckoo hash info to sender.
        channel.write(&nbins)?;

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
    use swanky_rng::SwankyRng;

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 16;

    #[test]
    fn test_psi_complete_intersection() {
        let mut rng = SwankyRng::new();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        swanky_channel::local::local_channel_pair(
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Sender::init(channel, &mut rng)?;
                psi.send(&sender_inputs, channel, &mut rng)
            },
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Receiver::init(channel, &mut rng)?;
                let intersection = psi.receive(&receiver_inputs, channel, &mut rng)?;
                assert_eq!(intersection.len(), SET_SIZE);
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn test_payloads() {
        let mut rng = SwankyRng::new();
        let intersection_size = SET_SIZE / 2;
        let intersection = rand_vec_vec(intersection_size, ITEM_SIZE, &mut rng);

        let mut sender_inputs = rand_vec_vec(SET_SIZE - intersection_size, ITEM_SIZE, &mut rng);
        let mut receiver_inputs = rand_vec_vec(SET_SIZE - intersection_size, ITEM_SIZE, &mut rng);
        sender_inputs.extend(intersection.clone());
        receiver_inputs.extend(intersection);

        let (sender_payloads, receiver_payloads) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Sender::init(channel, &mut rng)?;
                psi.send_payloads(&sender_inputs, channel, &mut rng)
            },
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Receiver::init(channel, &mut rng)?;
                psi.receive_payloads(&receiver_inputs, channel, &mut rng)
            },
        )
        .unwrap();
        assert_eq!(receiver_payloads.len(), intersection_size);

        for (item, payload) in sender_inputs.iter().zip(sender_payloads.iter()) {
            if let Some(other_payload) = receiver_payloads.get(item) {
                assert_eq!(payload, other_payload);
            }
        }
    }
}
