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
use fancy_garbling::{BinaryBundle, BundleGadgets, CrtBundle, CrtGadgets, Fancy, FancyInput};
use itertools::Itertools;
use ocelot::oprf::{kmprt, ProgrammableReceiver, ProgrammableSender};
use ocelot::ot::{KosReceiver as OtReceiver, KosSender as OtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests.
const HASH_SIZE: usize = 4;

/// The type of values in the sender and receiver's sets.
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
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let opprf = kmprt::KmprtSender::init(channel, rng)?;
        Ok(Self { opprf, state: None })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        channel: &mut C,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<(), Error> {
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

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state {
            s
        } else {
            return Err(Error::PsiProtocolError(
                "send/receive must be called first".to_string(),
            ));
        };

        let mut gb = twopac::semihonest::Garbler::<C, RNG, OtSender>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
            &[],
        )?;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&mods)?;
        let outs = fancy_compute_intersection(&mut gb, &sender_inputs, &receiver_inputs)?;
        gb.outputs(&outs)?;

        Ok(())
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state {
            s
        } else {
            return Err(Error::PsiProtocolError(
                "send/receive must be called first".to_string(),
            ));
        };

        let mut gb = twopac::semihonest::Garbler::<C, RNG, OtSender>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
            &[],
        )?;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&mods)?;
        let (outs, _) = fancy_compute_cardinality(&mut gb, &sender_inputs, &receiver_inputs)?;
        gb.outputs(&outs)?;

        Ok(())
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let opprf = kmprt::KmprtReceiver::init(channel, rng)?;
        Ok(Self { opprf, state: None })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        channel: &mut C,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let key = rng.gen();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        // Send cuckoo hash info to receiver.
        channel.write_block(&key)?;
        channel.write_usize(cuckoo.nbins)?;
        channel.flush()?;

        // Build `table` to include a cuckoo hash entry xored with its hash
        // index, if such a entry exists, or a random value.
        let table = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => item.entry ^ Block::from(item.hash_index as u128),
                None => rng.gen(),
            })
            .collect::<Vec<Block>>();

        let opprf_outputs = self.opprf.receive(channel, 0, &table, rng)?;

        self.state = Some(ReceiverState {
            opprf_outputs,
            cuckoo,
            inputs: inputs.to_vec(),
        });

        Ok(())
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Msg>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state {
            s
        } else {
            return Err(Error::PsiProtocolError(
                "send/receive must be called first".to_string(),
            ));
        };
        let nbins = state.cuckoo.nbins;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mut ev = twopac::semihonest::Evaluator::<C, RNG, OtReceiver>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.receive_many(&mods)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods)?;

        let outs = fancy_compute_intersection(&mut ev, &sender_inputs, &receiver_inputs)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;

        let mut intersection = Vec::new();

        for (opt_item, in_intersection) in state.cuckoo.items.iter().zip_eq(mpc_outs.into_iter()) {
            if let Some(item) = opt_item {
                if in_intersection == 1_u16 {
                    intersection.push(state.inputs[item.input_index].clone());
                }
            }
        }

        Ok(intersection)
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<usize, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let state = if let Some(s) = &self.state {
            s
        } else {
            return Err(Error::PsiProtocolError(
                "send/receive must be called first".to_string(),
            ));
        };
        let nbins = state.cuckoo.nbins;

        let my_input_bits = encode_inputs(&state.opprf_outputs);

        let mut ev = twopac::semihonest::Evaluator::<C, RNG, OtReceiver>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.receive_many(&mods)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods)?;

        let (outs, mods) = fancy_compute_cardinality(&mut ev, &sender_inputs, &receiver_inputs)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;

        let cardinality = fancy_garbling::util::crt_inv(&mpc_outs, &mods);

        Ok(cardinality as usize)
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

/// Fancy function to compute the cardinaility and return CRT value containing the result
/// along with the moduli of that value.
fn fancy_compute_cardinality<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<(Vec<F::Item>, Vec<u16>), F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let eqs = sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect::<Result<Vec<F::Item>, F::Error>>()?;

    let qs = fancy_garbling::util::primes_with_width(16);
    let q = fancy_garbling::util::product(&qs);
    let mut acc = f.crt_constant_bundle(0, q)?;
    let one = f.crt_constant_bundle(1, q)?;

    for b in eqs.into_iter() {
        let b_ws = one
            .iter()
            .map(|w| f.mul(w, &b))
            .collect::<Result<Vec<F::Item>, F::Error>>()?;
        let b_crt = CrtBundle::new(b_ws);
        acc = f.crt_add(&acc, &b_crt)?;
    }

    Ok((acc.wires().to_vec(), qs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 6;

    #[test]
    fn full_protocol() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE);
        let receiver_inputs = sender_inputs.clone();

        std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Block::from(1));
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

            psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
            psi.compute_cardinality(&mut channel, &mut rng).unwrap();
            // psi.compute_intersection(&mut channel, &mut rng).unwrap();
        });

        let mut rng = AesRng::from_seed(Block::from(1));
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

        psi.receive(&mut channel, &receiver_inputs, &mut rng)
            .unwrap();
        let cardinality = psi.compute_cardinality(&mut channel, &mut rng).unwrap();
        // let intersection = psi.compute_intersection(&mut channel, &mut rng).unwrap();

        // assert_eq!(intersection.len(), SET_SIZE);
        assert_eq!(cardinality, SET_SIZE);
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
        for (opt_item, bin) in cuckoo.items.iter().zip_eq(&table) {
            if let Some(item) = opt_item {
                assert!(
                    bin.iter()
                        .any(|bin_elem| *bin_elem
                            == item.entry ^ Block::from(item.hash_index as u128))
                );
            }
        }
    }
}
