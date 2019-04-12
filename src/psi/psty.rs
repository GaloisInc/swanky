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
use ocelot::oprf::kkrt;
// use ocelot::oprf::{self, Receiver as OprfReceiver, Sender as OprfSender};
// use rand::seq::SliceRandom;
use rand::{Rng, CryptoRng, RngCore};
// use scuttlebutt::utils as scutils;
use scuttlebutt::{Block, SemiHonest};
// use sha2::{Digest, Sha256};
// use std::collections::HashSet;
use std::io::{Read, Write};

use ocelot::oprf::kmprt;
use ocelot::oprf::{ProgrammableReceiver, ProgrammableSender};

const NHASHES: usize = 3;

pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct P1 {
    opprf: kmprt::KmprtReceiver,
}

/// Private set intersection receiver.
pub struct P2 {
    opprf: kmprt::KmprtSender,
}

impl P1 {
    pub fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            opprf: kmprt::KmprtReceiver::init(reader, writer, rng)?,
        })
    }

    pub fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Msg],
        mut rng: &mut RNG,
    ) -> Result<Vec<kkrt::Output>, Error> {
        let n = inputs.len();

        let key = rand::random::<Block>();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        let nbins = cuckoo.nbins;
        assert_eq!(cuckoo.stashsize, 0);

        println!("n={} nbins={}", n, nbins);

        // Send cuckoo hash info to receiver.
        key.write(writer)?;
        stream::write_usize(writer, nbins)?;
        writer.flush()?;

        // Fill in table with default values
        let table = cuckoo
            .items()
            .map(|opt_item| {
                opt_item
                    .as_ref()
                    .map_or(Block::default(), |item| item.entry)
            })
            .collect::<Vec<Block>>();

        let outputs = self.opprf.receive(reader, writer, 0, &table, rng)?;

        Ok(outputs)
    }
}

impl P2 {
    pub fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            opprf: kmprt::KmprtSender::init(reader, writer, rng)?,
        })
    }

    pub fn send<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<Vec<kkrt::Output>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        // receive cuckoo hash info from sender
        let key = Block::read(reader)?;
        let nbins = stream::read_usize(reader)?;

        let mut inputs = utils::compress_and_hash_inputs(inputs, key);
        let n = inputs.len();

        inputs.sort();
        inputs.dedup();

        // map inputs to table using all hash functions
        let mut table = vec![Vec::new(); nbins];

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
        let points = table.into_iter().zip(ts.iter()).flat_map(|(bin,t)| {
            // map all the points in a bin to the same tag
            bin.into_iter().map(move |item| (item, t.clone()))
        }).collect::<Vec<(Block, kkrt::Output)>>();

        let mut check = points.iter().map(|(x,_)| x.clone()).collect::<Vec<_>>();
        check.sort();
        check.dedup();
        assert_eq!(check.len(), points.len());

        let _ = self.opprf.send(reader, writer, &points, points.len(), nbins, rng)?;

        // return the target values for input to the MPC
        Ok(ts)
    }
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
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);

            let start = SystemTime::now();
            let mut psi = P1::init(&mut reader, &mut writer, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            let start = SystemTime::now();
            psi.send(&mut reader, &mut writer, &sender_inputs, &mut rng)
                .unwrap();
            println!(
                "[{}] Send time: {} ms",
                SET_SIZE,
                start.elapsed().unwrap().as_millis()
            );
        });

        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);

        let start = SystemTime::now();
        let mut psi = P2::init(&mut reader, &mut writer, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );

        let start = SystemTime::now();
        let intersection = psi
            .send(&mut reader, &mut writer, &receiver_inputs, &mut rng)
            .unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            SET_SIZE,
            start.elapsed().unwrap().as_millis()
        );

        handle.join().unwrap();
    }
}
