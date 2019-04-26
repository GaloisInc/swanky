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
use rand::Rng;
use scuttlebutt::{AesRng, Block};
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::rc::Rc;

use fancy_garbling::{BinaryGadgets, BundleGadgets, Fancy, FancyError, HasModulus};

const NHASHES: usize = 3;
const HASH_SIZE: usize = 4; // how many bytes of the hash to use for the equality tests

pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender<R: Read + Send + Debug, W: Write + Send + Debug + 'static> {
    opprf: kmprt::KmprtReceiver,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
    rng: AesRng,
}

/// Private set intersection receiver.
pub struct Receiver<R, W> {
    opprf: kmprt::KmprtSender,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
    rng: AesRng,
}

impl<R: Read + Send + Debug, W: Write + Send + Debug + 'static> Sender<R, W> {
    pub fn init(
        reader: Rc<RefCell<R>>,
        writer: Rc<RefCell<W>>,
    ) -> Result<Self, Error> {
        let mut rng = AesRng::new();
        let opprf =
            kmprt::KmprtReceiver::init(&mut *reader.borrow_mut(), &mut *writer.borrow_mut(), &mut rng)?;
        Ok(Self {
            opprf,
            reader,
            writer,
            rng,
        })
    }

    pub fn send(&mut self, inputs: &[Msg]) -> Result<(), Error>
    {
        let key = self.rng.gen();
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
            &mut self.rng,
        )?;

        let gb_inps = opprf_outputs
            .iter()
            .flat_map(|blk| {
                blk.prefix(HASH_SIZE)
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| ((byte >> i) & 1_u8) as u16).collect_vec())
            })
            .collect::<Vec<u16>>();

        let mut gb = twopac::semihonest::Garbler::<R, W, AesRng, OtSender>::new(
            self.reader.clone(),
            self.writer.clone(),
            &gb_inps,
            self.rng.fork(),
        )?;
        compute_intersection(&mut gb, opprf_outputs.len(), HASH_SIZE * 8)?;

        Ok(())
    }
}

impl<R: Read + Send + Debug + 'static, W: Write + Send + Debug + 'static> Receiver<R, W> {
    pub fn init(
        reader: Rc<RefCell<R>>,
        writer: Rc<RefCell<W>>,
    ) -> Result<Self, Error>
    {
        let mut rng = AesRng::new();
        let opprf =
            kmprt::KmprtSender::init(&mut *reader.borrow_mut(), &mut *writer.borrow_mut(), &mut rng)?;
        Ok(Self {
            opprf,
            reader,
            writer,
            rng,
        })
    }

    pub fn receive(&mut self, inputs: &[Msg]) -> Result<Vec<Msg>, Error>
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
                table[bins[0]].push(self.rng.gen());
            }
        }

        // select the target values
        let ts = (0..nbins).map(|_| self.rng.gen()).collect::<Vec<kkrt::Output>>();
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
            &mut self.rng,
        )?;

        let ev_inps = ts
            .iter()
            .flat_map(|blk| {
                blk.prefix(HASH_SIZE)
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| ((byte >> i) & 1_u8) as u16).collect_vec())
            })
            .collect::<Vec<u16>>();

        let mut ev = twopac::semihonest::Evaluator::<R, W, AesRng, OtReceiver>::new(
            self.reader.clone(),
            self.writer.clone(),
            &ev_inps,
            self.rng.fork(),
        )?;
        compute_intersection(&mut ev, ts.len(), HASH_SIZE * 8)?;
        let outs = ev.decode_output();

        unimplemented!()
    }
}

/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn compute_intersection<F, W, E>(
    f: &mut F,
    ninputs: usize,
    input_size: usize,
) -> Result<(), E>
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

    f.outputs(&res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
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
            let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
            let writer = Rc::new(RefCell::new(BufWriter::new(sender)));

            let start = SystemTime::now();
            let mut psi = Sender::init(reader, writer).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            let start = SystemTime::now();
            psi.send(&sender_inputs).unwrap();
            println!(
                "[{}] Send time: {} ms",
                SET_SIZE,
                start.elapsed().unwrap().as_millis()
            );
        });

        let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
        let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));

        let start = SystemTime::now();
        let mut psi = Receiver::init(reader.clone(), writer.clone()).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        let _ = psi.receive(&receiver_inputs).unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );

        handle.join().unwrap();
    }
}
