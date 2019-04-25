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
use itertools::Itertools;
use ocelot::oprf::kkrt;
use ocelot::oprf::kmprt;
use ocelot::oprf::{ProgrammableReceiver, ProgrammableSender};
use ocelot::ot::{ChouOrlandiReceiver as OtReceiver, ChouOrlandiSender as OtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block};
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::rc::Rc;

use fancy_garbling::{BinaryGadgets, BundleGadgets, Fancy, FancyError, HasModulus};

const NHASHES: usize = 3;

pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct P1<R, W> {
    opprf: kmprt::KmprtReceiver,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

/// Private set intersection receiver.
pub struct P2<R, W> {
    opprf: kmprt::KmprtSender,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
}

impl<R, W> P1<R, W> {
    pub fn init<RNG>(
        reader: Rc<RefCell<R>>,
        writer: Rc<RefCell<W>>,
        rng: &mut RNG,
    ) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send + Debug,
        RNG: CryptoRng + RngCore + SeedableRng,
    {
        let opprf =
            kmprt::KmprtReceiver::init(&mut *reader.borrow_mut(), &mut *writer.borrow_mut(), rng)?;
        Ok(Self {
            opprf,
            reader,
            writer,
        })
    }

    pub fn send<RNG>(&mut self, inputs: &[Msg], rng: &mut RNG) -> Result<Vec<kkrt::Output>, Error>
    where
        R: Read + Send,
        W: Write + Send + std::fmt::Debug + 'static,
        RNG: CryptoRng + RngCore + SeedableRng,
    {
        let key = rng.gen::<Block>();
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
            .map(|opt_item| {
                opt_item
                    .as_ref()
                    .map_or(Block::default(), |item| item.entry)
            })
            .collect::<Vec<Block>>();

        let opprf_outputs = self.opprf.receive(
            &mut *self.reader.borrow_mut(),
            &mut *self.writer.borrow_mut(),
            0,
            &table,
            rng,
        )?;

        let gb_inps = opprf_outputs
            .iter()
            .flat_map(|blk| {
                blk.prefix(16)
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| ((byte >> i) & 1_u8) as u16).collect_vec())
            })
            .collect::<Vec<u16>>();

        let mut gb = twopac::semihonest::Garbler::<R, W, AesRng, OtSender>::new(
            self.reader.clone(),
            self.writer.clone(),
            &gb_inps,
            AesRng::from_seed(rng.gen::<Block>()),
        )?;

        let _res = compute_intersection(&mut gb, gb_inps.len(), 128)?;

        Ok(opprf_outputs)
    }
}

impl<R, W> P2<R, W> {
    pub fn init<RNG>(
        reader: Rc<RefCell<R>>,
        writer: Rc<RefCell<W>>,
        rng: &mut RNG,
    ) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let opprf =
            kmprt::KmprtSender::init(&mut *reader.borrow_mut(), &mut *writer.borrow_mut(), rng)?;
        Ok(Self {
            opprf,
            reader,
            writer,
        })
    }

    pub fn send<RNG>(&mut self, inputs: &[Msg], rng: &mut RNG) -> Result<Vec<kkrt::Output>, Error>
    where
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug,
        RNG: CryptoRng + RngCore,
    {
        // receive cuckoo hash info from sender
        let key = Block::read(&mut *self.reader.borrow_mut())?;
        let nbins = stream::read_usize(&mut *self.reader.borrow_mut())?;

        let inputs = utils::compress_and_hash_inputs(inputs, key);

        // map inputs to table using all hash functions
        let mut table = vec![Vec::with_capacity(inputs.len()); nbins];

        for &x in &inputs {
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
        let ts = (0..nbins).map(|_| rng.gen()).collect::<Vec<kkrt::Output>>();
        let points = table
            .into_iter()
            .zip(ts.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, t.clone()))
            })
            .collect::<Vec<(Block, kkrt::Output)>>();

        let _ = self.opprf.send(
            &mut *self.reader.borrow_mut(),
            &mut *self.writer.borrow_mut(),
            &points,
            points.len(),
            nbins,
            rng,
        )?;

        let ev_inps = ts
            .iter()
            .flat_map(|blk| {
                blk.prefix(16)
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| ((byte >> i) & 1_u8) as u16).collect_vec())
            })
            .collect::<Vec<u16>>();

        let mut ev = twopac::semihonest::Evaluator::<R, W, AesRng, OtReceiver>::new(
            self.reader.clone(),
            self.writer.clone(),
            &ev_inps,
            AesRng::from_seed(rng.gen::<Block>()),
        )?;

        let _res = compute_intersection(&mut ev, ev_inps.len(), 128)?;

        // return the target values for input to the MPC
        Ok(ts)
    }
}

/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn compute_intersection<F, W, E>(
    f: &mut F,
    ninputs: usize,
    input_size: usize,
) -> Result<Vec<W>, E>
where
    F: Fancy<Item = W, Error = E>,
    W: Clone + HasModulus,
    E: std::fmt::Debug + std::fmt::Display + From<FancyError>,
{
    let p1_inps = f.bin_garbler_input_bundles(input_size, ninputs, None)?;
    let p2_inps = f.bin_evaluator_input_bundles(input_size, ninputs)?;

    let mut res = Vec::with_capacity(p1_inps.len());

    for (p1, p2) in p1_inps.into_iter().zip(p2_inps.into_iter()) {
        let eq = f.eq_bundles(p1.borrow(), p2.borrow())?;
        res.push(eq);
    }

    Ok(res)
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
    const SET_SIZE: usize = 1 << 8;

    #[test]
    fn test_psi() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE);
        let receiver_inputs = sender_inputs.clone();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
            let writer = Rc::new(RefCell::new(BufWriter::new(sender)));

            let start = SystemTime::now();
            let mut psi = P1::init(reader, writer, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            let start = SystemTime::now();
            psi.send(&sender_inputs, &mut rng).unwrap();
            println!(
                "[{}] Send time: {} ms",
                SET_SIZE,
                start.elapsed().unwrap().as_millis()
            );
        });

        let mut rng = AesRng::new();
        let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
        let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));

        let start = SystemTime::now();
        let mut psi = P2::init(reader.clone(), writer.clone(), &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        let _ = psi.send(&receiver_inputs, &mut rng).unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );

        handle.join().unwrap();
    }
}
