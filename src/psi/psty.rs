// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Tkachenko-Yanai private set intersection
//! protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::cuckoo::CuckooHash;
use crate::errors::Error;
use crate::utils;
use fancy_garbling::{BinaryBundle, BundleGadgets, Fancy};
use itertools::Itertools;
use ocelot::oprf::{kmprt, ProgrammableReceiver, ProgrammableSender};
use ocelot::ot::{KosReceiver as OtReceiver, KosSender as OtSender};
use rand::Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use scuttlebutt::{Block, Block512, Channel};
use std::fmt::Debug;
use std::io::{Read, Write};

const NHASHES: usize = 3;
const HASH_SIZE: usize = 4; // how many bytes of the hash to use for the equality tests

/// The type of values in the Sender & Receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    opprf: kmprt::KmprtSender,
    state: Option<SenderState>,
}

struct SenderState {
    opprf_outputs: Vec<Block512>,
}

/// Private set intersection receiver.
pub struct Receiver {
    opprf: kmprt::KmprtReceiver,
    state: Option<ReceiverState>,
}

struct ReceiverState {
    opprf_outputs: Vec<Block512>,
    cuckoo: CuckooHash,
    inputs: Vec<Msg>,
}

impl Sender {
    pub fn init<R, W, RNG>(channel: &mut Channel<R, W>, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read,
        W: Write,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        let opprf = kmprt::KmprtSender::init(channel, rng)?;
        Ok(Self {
            opprf,
            state: None,
        })
    }

    pub fn send<R, W, RNG>(
        &mut self,
        channel: &mut Channel<R, W>,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        R: Read + Send + Debug,
        W: Write + Send + Debug + 'static,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        // receive cuckoo hash info from sender
        let key = channel.read_block()?;
        let hashes = utils::compress_and_hash_inputs(inputs, key);

        // map inputs to table using all hash functions
        let nbins = channel.read_usize()?;
        let mut table = vec![Vec::new(); nbins];

        for &x in &hashes {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(x, h, nbins);
                table[bin].push(x ^ Block::from(h as u128));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j].
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
            }
        }

        // select the target values
        let ts = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();

        let points = table
            .into_iter()
            .zip_eq(ts.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, t.clone()))
            })
            .collect_vec();

        let _ = self
            .opprf
            .send(channel, &points, points.len(), nbins, rng)?;

        self.state = Some(SenderState { opprf_outputs: ts });

        Ok(())
    }

    pub fn compute_intersection<R, W, RNG>(&mut self, channel: &mut Channel<R,W>, rng: &mut RNG) -> Result<(), Error>
    where
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug + 'static,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state { s } else { return Err(Error::PstyProtocolError("send/receive must be called first".to_string())) };

        let mut gb = twopac::semihonest::Garbler::<R, W, RNG, OtSender>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
            &[],
        )?;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.garbler_inputs(&my_input_bits, &mods)?;
        let receiver_inputs = gb.evaluator_inputs(&mods)?;
        let outs = fancy_compute_intersection(&mut gb, &sender_inputs, &receiver_inputs)?;
        gb.outputs(&outs)?;

        Ok(())
    }
}

impl Receiver {
    pub fn init<R, W, RNG>(channel: &mut Channel<R, W>, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read,
        W: Write,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let opprf = kmprt::KmprtReceiver::init(channel, rng)?;
        Ok(Self {
            opprf,
            state: None,
        })
    }

    pub fn receive<R, W, RNG>(
        &mut self,
        channel: &mut Channel<R, W>,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let key = rng.gen();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        let nbins = cuckoo.nbins;
        assert_eq!(cuckoo.stashsize, 0);

        // Send cuckoo hash info to receiver.
        channel.write_block(&key)?;
        channel.write_usize(nbins)?;
        channel.flush()?;

        // Fill in table with default values
        let table = cuckoo
            .items()
            .map(|opt_item| match opt_item {
                Some(item) => {
                    item.entry
                        ^ Block::from(
                            item.hash_index
                                .expect("cuckoo must be stash-less for this protocol")
                                as u128,
                        )
                }
                None => rng.gen(),
            })
            .collect_vec();

        let opprf_outputs = self.opprf.receive(channel, 0, &table, rng)?;

        self.state = Some(ReceiverState {
            opprf_outputs,
            cuckoo,
            inputs: inputs.to_vec(),
        });

        Ok(())
    }

    pub fn compute_intersection<R, W, RNG>(&mut self, channel: &mut Channel<R,W>, rng: &mut RNG) -> Result<Vec<Msg>, Error>
    where
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state { s } else { return Err(Error::PstyProtocolError("send/receive must be called first".to_string())) };
        let nbins = state.cuckoo.nbins;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mut ev = twopac::semihonest::Evaluator::<R, W, RNG, OtReceiver>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.garbler_inputs(&mods)?;
        let receiver_inputs = ev.evaluator_inputs(&my_input_bits, &mods)?;

        let outs = fancy_compute_intersection(&mut ev, &sender_inputs, &receiver_inputs)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;

        let mut intersection = Vec::new();

        for (opt_item, in_intersection) in state.cuckoo.items().into_iter().zip_eq(mpc_outs.into_iter()) {
            if let Some(item) = opt_item {
                if in_intersection == 1_u16 {
                    intersection.push(state.inputs[item.input_index].clone());
                }
            }
        }

        Ok(intersection)
    }
}

fn encode_inputs(opprf_outputs: &[Block512]) -> Vec<u16> {
    opprf_outputs
        .iter()
        .flat_map(|blk| {
            blk.prefix(HASH_SIZE)
                .iter()
                .flat_map(|byte| (0..8).map(|i| ((byte >> i) & 1_u8) as u16).collect_vec())
        })
        .collect()
}

/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn fancy_compute_intersection<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<Vec<F::Item>, F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());

    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::time::SystemTime;

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 6;

    #[test]
    fn full_protocol() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        // let sender_inputs = (0..SET_SIZE).map(|x| (0..ITEM_SIZE).map(|i| ((x >> i) & 0xff) as u8).collect_vec()).collect_vec();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE);
        let receiver_inputs = sender_inputs.clone();

        std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Block::from(1));

            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let start = SystemTime::now();
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            let start = SystemTime::now();
            psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
            psi.compute_intersection(&mut channel, &mut rng).unwrap();
            println!(
                "[{}] Send time: {} ms",
                SET_SIZE,
                start.elapsed().unwrap().as_millis()
            );
        });

        let mut rng = AesRng::from_seed(Block::from(1));

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let start = SystemTime::now();
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        psi.receive(&mut channel, &receiver_inputs, &mut rng)
            .unwrap();
        let intersection = psi.compute_intersection(&mut channel, &mut rng).unwrap();

        println!(
            "[{}] Receiver time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );

        assert_eq!(intersection.len(), SET_SIZE);
    }

    #[test]
    fn hashing() {
        let mut rng = AesRng::new();
        let inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE);

        let key = rng.gen();
        let hashes = utils::compress_and_hash_inputs(&inputs, key);
        let cuckoo = CuckooHash::new(&hashes, NHASHES).unwrap();

        // map inputs to table using all hash functions
        let mut table = vec![Vec::new(); cuckoo.nbins];

        for &x in &hashes {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(x, h, cuckoo.nbins);
                table[bin].push(x ^ Block::from(h as u128));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j].
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
            }
        }

        // each item in a cuckoo bin should also be in one of the table bins
        for (opt_item, bin) in cuckoo.items().zip_eq(&table) {
            if let Some(item) = opt_item {
                assert!(bin.iter().any(|bin_elem| *bin_elem
                    == item.entry ^ Block::from(item.hash_index.unwrap() as u128)));
            }
        }
    }
}
