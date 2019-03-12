// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the batched, related-key oblivious pseudorandom function
//! (BaRK-OPRF) protocol of Kolesnikov, Kumaresan, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2016/799>, Figure 2).

use super::prc::PseudorandomCode;
use crate::errors::Error;
use crate::{
    cointoss, stream, utils, ObliviousPrfReceiver, ObliviousPrfSender, ObliviousTransferReceiver,
    ObliviousTransferSender,
};
use arrayref::array_ref;
use rand::CryptoRng;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block, SemiHonest};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::marker::PhantomData;

pub struct Seed([u8; 64]);
#[derive(Clone, Copy)]
pub struct Output([u8; 64]);

impl Default for Seed {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Output {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut data = [0u8; 64];
        reader.read_exact(&mut data)?;
        let output = unsafe { std::mem::transmute(data) };
        Ok(Self(output))
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write(&self.0)?;
        Ok(())
    }
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Output {{ {:?} }}", self.0.to_vec())
    }
}

impl Default for Output {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Eq for Output {}

impl Hash for Output {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_vec().hash(state);
    }
}

impl Ord for Output {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_vec().cmp(&other.0.to_vec())
    }
}

impl PartialEq for Output {
    fn eq(&self, other: &Output) -> bool {
        self.0.to_vec() == other.0.to_vec()
    }
}

impl PartialOrd for Output {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.to_vec().cmp(&other.0.to_vec()))
    }
}

pub struct KkrtOPRFSender<OT: ObliviousTransferReceiver + SemiHonest> {
    _ot: PhantomData<OT>,
    s: Vec<bool>,
    s_: Vec<u8>,
    code: PseudorandomCode,
    rngs: Vec<AesRng>,
}

pub struct KkrtOPRFReceiver<OT: ObliviousTransferSender + SemiHonest> {
    _ot: PhantomData<OT>,
    code: PseudorandomCode,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> ObliviousPrfSender
    for KkrtOPRFSender<OT>
{
    type Seed = Seed;
    type Input = Block;
    type Output = Output;

    fn init<R, W, RNG>(reader: &mut R, writer: &mut W, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let mut ot = OT::init(reader, writer, rng)?;
        let mut s_ = [0u8; 64];
        rng.fill_bytes(&mut s_);
        let s = utils::u8vec_to_boolvec(&s_);
        let seeds = (0..4)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        let keys = cointoss::send(reader, writer, &seeds)?;
        let code = PseudorandomCode::new(keys[0], keys[1], keys[2], keys[3]);
        let ks = ot.receive(reader, writer, &s, rng)?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            s,
            s_: s_.to_vec(),
            code,
            rngs,
        })
    }

    fn send<R, W, RNG>(
        &mut self,
        reader: &mut R,
        _: &mut W,
        m: usize,
        _: &mut RNG,
    ) -> Result<Vec<Self::Seed>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let m = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        let (nrows, ncols) = (m, 512);
        let mut t0 = vec![0u8; nrows / 8];
        let mut t1 = vec![0u8; nrows / 8];
        let mut qs = vec![0u8; nrows * ncols / 8];
        for (j, b) in self.s.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            stream::read_bytes_inplace(reader, &mut t0)?;
            stream::read_bytes_inplace(reader, &mut t1)?;
            self.rngs[j].fill_bytes(&mut q);
            if *b {
                utils::xor_inplace(&mut q, &t1);
            } else {
                utils::xor_inplace(&mut q, &t0);
            }
        }
        let qs = utils::transpose(&qs, ncols, nrows);
        let seeds = qs
            .chunks(ncols / 8)
            .map(|q| Seed(*array_ref![q, 0, 64]))
            .collect();
        Ok(seeds)
    }

    fn compute(&self, seed: &Self::Seed, input: &Self::Input) -> Self::Output {
        let c = self.code.encode(*input);
        let tmp = utils::and(&c, &self.s_);
        let out = utils::xor(&seed.0, &tmp);
        Output(*array_ref![out, 0, 64])
    }
}

impl<OT: ObliviousTransferSender<Msg = Block> + SemiHonest> ObliviousPrfReceiver
    for KkrtOPRFReceiver<OT>
{
    type Input = Block;
    type Output = Output;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let mut ot = OT::init(reader, writer, rng)?;
        let seeds = (0..4)
            .map(|_| rand::random::<Block>())
            .collect::<Vec<Block>>();
        let keys = cointoss::receive(reader, writer, &seeds)?;
        let code = PseudorandomCode::new(keys[0], keys[1], keys[2], keys[3]);
        let mut ks = Vec::with_capacity(512);
        let mut k0 = Block::zero();
        let mut k1 = Block::zero();
        for _ in 0..512 {
            rng.fill_bytes(&mut k0.as_mut());
            rng.fill_bytes(&mut k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(reader, writer, &ks, rng)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            code,
            rngs,
        })
    }

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        _: &mut R,
        writer: &mut W,
        selections: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error> {
        let m = selections.len();
        let m = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        let (nrows, ncols) = (m, 512);
        let mut t0s = vec![0u8; nrows * ncols / 8];
        let mut t1s = vec![0u8; nrows * ncols / 8];
        let mut out = Vec::with_capacity(m);
        for (j, r) in selections.iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t0 = &mut t0s[range];
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t1 = &mut t1s[range];
            rng.fill_bytes(&mut t0);
            let c = self.code.encode(*r);
            utils::xor_inplace(&mut t1, &t0);
            utils::xor_inplace(&mut t1, &c);
            out.push(Output(*array_ref![t0, 0, 64]))
        }
        let t0s_ = utils::transpose(&t0s, nrows, ncols);
        let t1s_ = utils::transpose(&t1s, nrows, ncols);
        let mut t = vec![0u8; nrows / 8];
        for j in 0..self.rngs.len() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t0 = &t0s_[range];
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t1 = &t1s_[range];
            self.rngs[j].0.fill_bytes(&mut t);
            utils::xor_inplace(&mut t, &t0);
            stream::write_bytes(writer, &t)?;
            self.rngs[j].1.fill_bytes(&mut t);
            utils::xor_inplace(&mut t, &t1);
            stream::write_bytes(writer, &t)?;
        }
        writer.flush()?;
        Ok(out)
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> SemiHonest for KkrtOPRFSender<OT> {}
impl<OT: ObliviousTransferSender<Msg = Block> + SemiHonest> SemiHonest for KkrtOPRFReceiver<OT> {}

use crate::{alsz, chou_orlandi};

pub type KkrtSender = KkrtOPRFSender<alsz::AlszOTReceiver<chou_orlandi::ChouOrlandiOTSender>>;
pub type KkrtReceiver = KkrtOPRFReceiver<alsz::AlszOTSender<chou_orlandi::ChouOrlandiOTReceiver>>;

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::oprf::ObliviousPrfReceiver;
    use crate::ot::chou_orlandi;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    type KkrtSender = KkrtOPRFSender<chou_orlandi::ChouOrlandiOTReceiver>;
    type KkrtReceiver = KkrtOPRFReceiver<chou_orlandi::ChouOrlandiOTSender>;

    fn _test_oprf(n: usize) {
        let selections = rand_block_vec(n);
        let selections_ = selections.clone();
        let results = Arc::new(Mutex::new(vec![]));
        let results_ = results.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut oprf = KkrtSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let seeds = oprf.send(&mut reader, &mut writer, n, &mut rng).unwrap();
            let mut results = results.lock().unwrap();
            *results = selections_
                .iter()
                .zip(seeds.iter())
                .map(|(inp, seed)| oprf.compute(seed, inp))
                .collect::<Vec<Output>>();
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
        for j in 0..n {
            assert_eq!(results_[j].0.to_vec(), outputs[j].0.to_vec());
        }
    }

    #[test]
    fn test_oprf() {
        _test_oprf(8);
        _test_oprf(11);
        _test_oprf(64);
    }
}
