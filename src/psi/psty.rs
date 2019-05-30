// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Tkachenko-Yanai private set intersection
//! protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::cuckoo::CuckooHash;
use crate::stream;
use crate::utils;
use crate::Error;
use fancy_garbling::{BinaryBundle, BundleGadgets, Fancy};
use itertools::Itertools;
use ocelot::oprf::kmprt;
use ocelot::oprf::{ProgrammableReceiver, ProgrammableSender};
use ocelot::ot::{ChouOrlandiReceiver, ChouOrlandiSender};
use rand::Rng;
use scuttlebutt::{AesRng, Block, Block512};
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::rc::Rc;
use rand_core::{CryptoRng, RngCore, SeedableRng};

const NHASHES: usize = 3;
const HASH_SIZE: usize = 4; // how many bytes of the hash to use for the equality tests

/// The type of values in the Sender & Receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender<R, W> {
    opprf: kmprt::KmprtSender,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

/// Private set intersection receiver.
pub struct Receiver<R, W> {
    opprf: kmprt::KmprtReceiver,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

impl<R: Read + Send + Debug + 'static, W: Write + Send + Debug + 'static> Sender<R, W> {
    pub fn init<RNG>(reader: Rc<RefCell<R>>, writer: Rc<RefCell<W>>, rng: &mut RNG) -> Result<Self, Error>
        where RNG: RngCore + CryptoRng + SeedableRng
    {
        let opprf = kmprt::KmprtSender::init(
            &mut *reader.borrow_mut(),
            &mut *writer.borrow_mut(),
            rng,
        )?;
        Ok(Self {
            opprf,
            reader,
            writer,
        })
    }

    pub fn send<RNG>(&mut self, inputs: &[Msg], rng: &mut RNG) -> Result<Vec<Block512>, Error>
        where RNG: RngCore + CryptoRng + SeedableRng<Seed=Block>
    {
        // receive cuckoo hash info from sender
        let key = Block::read(&mut *self.reader.borrow_mut())?;
        let hashes = utils::compress_and_hash_inputs(inputs, key);

        // map inputs to table using all hash functions
        let nbins = stream::read_usize(&mut *self.reader.borrow_mut())?;
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

        let _ = self.opprf.send(
            &mut *self.reader.borrow_mut(),
            &mut *self.writer.borrow_mut(),
            &points,
            points.len(),
            nbins,
            rng
        )?;

        let mut gb = twopac::semihonest::Garbler::<R, W, RNG, ChouOrlandiSender>::new(
            self.reader.clone(),
            self.writer.clone(),
            RNG::from_seed(rng.gen()),
            &[],
        )?;

        let my_input_bits = encode_inputs(&ts);

        let mods = vec![2; nbins * HASH_SIZE * 8]; // all binary moduli
        let sender_inputs = gb.garbler_inputs(&my_input_bits, &mods)?;
        let receiver_inputs = gb.evaluator_inputs(&mods)?;
        let outs = compute_intersection(&mut gb, &sender_inputs, &receiver_inputs)?;
        gb.outputs(&outs)?;

        Ok(ts)
    }
}

impl<R: Read + Send + Debug + 'static, W: Write + Send + Debug> Receiver<R, W> {
    pub fn init<RNG>(reader: Rc<RefCell<R>>, writer: Rc<RefCell<W>>, rng: &mut RNG) -> Result<Self, Error>
        where RNG: RngCore + CryptoRng + SeedableRng<Seed=Block>
    {
        let opprf = kmprt::KmprtReceiver::init(
            &mut *reader.borrow_mut(),
            &mut *writer.borrow_mut(),
            rng,
        )?;
        Ok(Self {
            opprf,
            reader,
            writer,
        })
    }

    pub fn receive<RNG>(&mut self, inputs: &[Msg], rng: &mut RNG) -> Result<(Vec<Block512>, Vec<Msg>), Error>
        where RNG: RngCore + CryptoRng + SeedableRng<Seed=Block>
    {
        let key = rng.gen();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        let nbins = cuckoo.nbins;
        assert_eq!(cuckoo.stashsize, 0);

        // Send cuckoo hash info to receiver.
        key.write(&mut *self.writer.borrow_mut())?;
        stream::write_usize(&mut *self.writer.borrow_mut(), nbins)?;
        self.writer.borrow_mut().flush()?;

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

        let opprf_outputs = self.opprf.receive(
            &mut *self.reader.borrow_mut(),
            &mut *self.writer.borrow_mut(),
            0,
            &table,
            rng,
        )?;

        let my_input_bits = encode_inputs(&opprf_outputs);

        let mut ev = twopac::semihonest::Evaluator::<R, W, RNG, ChouOrlandiReceiver>::new(
            self.reader.clone(),
            self.writer.clone(),
            RNG::from_seed(rng.gen()),
        )?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.garbler_inputs(&mods)?;
        let receiver_inputs = ev.evaluator_inputs(&my_input_bits, &mods)?;

        let outs = compute_intersection(&mut ev, &sender_inputs, &receiver_inputs)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;

        println!("{:?}", mpc_outs);

        let mut intersection = Vec::new();

        let items = cuckoo.items().collect_vec();

        assert_eq!(items.len(), mpc_outs.len());

        for (opt_item, in_intersection) in items.into_iter().zip_eq(mpc_outs.into_iter()) {
            if let Some(item) = opt_item {
                if in_intersection == 1_u16 {
                    intersection.push(inputs[item.input_index].clone());
                }
            }
        }

        Ok((opprf_outputs, intersection))
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
fn compute_intersection<F: Fancy>(
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
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::time::SystemTime;

    const ITEM_SIZE: usize = 2;
    const SET_SIZE: usize = 1 << 7;

    #[test]
    fn full_protocol() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        // let sender_inputs = (0..SET_SIZE).map(|x| (0..ITEM_SIZE).map(|i| ((x >> i) & 0xff) as u8).collect_vec()).collect_vec();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE);
        let receiver_inputs = sender_inputs.clone();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Block::from(1));

            let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
            let writer = Rc::new(RefCell::new(BufWriter::new(sender)));

            let start = SystemTime::now();
            let mut psi = Sender::init(reader, writer, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            let start = SystemTime::now();
            let sender_opprf_outputs = psi.send(&sender_inputs, &mut rng).unwrap();
            println!(
                "[{}] Send time: {} ms",
                SET_SIZE,
                start.elapsed().unwrap().as_millis()
            );
            sender_opprf_outputs
        });

        let mut rng = AesRng::from_seed(Block::from(1));

        let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
        let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));

        let start = SystemTime::now();
        let mut psi = Receiver::init(reader.clone(), writer.clone(), &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        let (receiver_opprf_outputs, intersection) = psi.receive(&receiver_inputs, &mut rng).unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );

        let sender_opprf_outputs = handle.join().unwrap();

        let mut size = 0;
        for (s, r) in sender_opprf_outputs
            .into_iter()
            .zip_eq(receiver_opprf_outputs.into_iter())
        {
            if s == r {
                size += 1;
            }
        }

        assert_eq!(size, SET_SIZE);

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
