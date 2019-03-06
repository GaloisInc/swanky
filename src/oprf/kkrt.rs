// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the batched, related-key oblivious pseudorandom function
//! (BaRK-OPRF) protocol of Kolesnikov, Kumaresan, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2016/799>, Figure 2).

use super::prc::PseudorandomCode;
use crate::{
    utils, ObliviousPrfReceiver, ObliviousPrfSender, ObliviousTransferReceiver,
    ObliviousTransferSender,
};
use failure::Error;
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};

pub struct KkrtOPRFSender<OT: ObliviousTransferReceiver> {
    ot: OT,
    s: Vec<bool>,
    s_: Vec<u8>,
}

pub struct KkrtOPRFReceiver<OT: ObliviousTransferSender> {
    ot: OT,
}

impl<OT: ObliviousTransferReceiver<Msg = Vec<u8>>> ObliviousPrfSender for KkrtOPRFSender<OT> {
    type Seed = (usize, Vec<u8>);
    type Input = Vec<u8>;
    type Output = (usize, Vec<u8>);

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(reader, writer, rng)?;
        let mut s_ = [0u8; 64];
        rng.fill_bytes(&mut s_);
        let s = utils::u8vec_to_boolvec(&s_);
        Ok(Self {
            ot,
            s,
            s_: s_.to_vec(),
        })
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Seed>, Error> {
        let (nrows, ncols) = (m, 512);
        // TODO: Choose C and send to R
        let qs = self.ot.receive(reader, writer, &self.s, rng)?;
        let qs = qs.into_iter().flatten().collect::<Vec<u8>>();
        let qs = utils::transpose(&qs, ncols, nrows);
        let seeds = qs
            .chunks(ncols / 8)
            .enumerate()
            .map(|(j, q)| (j, q.to_vec()))
            .collect();
        Ok(seeds)
    }

    fn compute(&self, seed: Self::Seed, input: Self::Input) -> Self::Output {
        let code = PseudorandomCode::new(vec![]);
        let c = code.encode(&input);
        let tmp = utils::and(&c, &self.s_);
        let out = utils::xor(&seed.1, &tmp);
        (seed.0, out)
    }
}

impl<OT: ObliviousTransferSender<Msg = Vec<u8>>> ObliviousPrfReceiver for KkrtOPRFReceiver<OT> {
    type Input = Vec<u8>;
    type Output = (usize, Vec<u8>);

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(reader, writer, rng)?;
        Ok(Self { ot })
    }

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        selections: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error> {
        let m = selections.len();
        let (nrows, ncols) = (m, 512);
        // TODO: Receive C
        let code = PseudorandomCode::new(vec![]);
        let mut t0s = vec![0u8; nrows * ncols / 8];
        let mut t1s = vec![0u8; nrows * ncols / 8];
        let mut out = Vec::with_capacity(m);
        for (j, r) in selections.iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t0 = &mut t0s[range];
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t1 = &mut t1s[range];
            rng.fill_bytes(&mut t0);
            let c = code.encode(r);
            utils::xor_inplace(&mut t1, &t0);
            utils::xor_inplace(&mut t1, &c);
            out.push((j, t0.to_vec()))
        }
        let t0s_ = utils::transpose(&t0s, nrows, ncols);
        let t1s_ = utils::transpose(&t1s, nrows, ncols);
        let mut ts = Vec::with_capacity(ncols);
        for j in 0..ncols {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t0 = t0s_[range].to_vec();
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t1 = t1s_[range].to_vec();
            ts.push((t0, t1));
        }
        self.ot.send(reader, writer, &ts, rng)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::oprf::ObliviousPrfReceiver;
    use crate::ot::dummy;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const T: usize = 16;

    fn rand_vec(t: usize) -> Vec<Vec<u8>> {
        (0..t)
            .map(|_| (0..64).map(|_| rand::random::<u8>()).collect::<Vec<u8>>())
            .collect()
    }

    type KkrtSender = KkrtOPRFSender<dummy::DummyVecOTReceiver>;
    type KkrtReceiver = KkrtOPRFReceiver<dummy::DummyVecOTSender>;

    #[test]
    fn test_oprf() {
        let selections = rand_vec(T);
        let selections_ = selections.clone();
        let results = Arc::new(Mutex::new(vec![]));
        let results_ = results.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut oprf = KkrtSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let seeds = oprf.send(&mut reader, &mut writer, T, &mut rng).unwrap();
            let mut results = results.lock().unwrap();
            *results = selections_
                .iter()
                .zip(seeds.iter())
                .map(|(inp, seed)| oprf.compute(seed.clone(), inp.to_vec()))
                .collect::<Vec<(usize, Vec<u8>)>>();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut oprf = KkrtReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let outputs = oprf
            .receive(&mut reader, &mut writer, &selections, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let results_ = results_.lock().unwrap();
        for j in 0..T {
            assert_eq!(results_[j], outputs[j])
        }
    }
}
