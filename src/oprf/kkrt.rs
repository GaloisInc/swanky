// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the batched, related-key oblivious pseudorandom function
//! (BaRK-OPRF) protocol of Kolesnikov, Kumaresan, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2016/799>, Figure 2).

#![allow(non_upper_case_globals)]

use super::prc::PseudorandomCode;
use crate::errors::Error;
use crate::{
    stream, utils, ObliviousPrf, ObliviousPrfReceiver, ObliviousPrfSender,
    ObliviousTransferReceiver, ObliviousTransferSender,
};
use arrayref::array_ref;
use rand::CryptoRng;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::utils as scutils;
use scuttlebutt::{cointoss, AesRng, Block, SemiHonest};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct Seed(pub [u8; 64]);
#[derive(Clone, Copy)]
pub struct Output(pub [u8; 64]);

impl Default for Seed {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Output {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut data = [0u8; 64];
        reader.read_exact(&mut data)?;
        Ok(Self(data))
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0
            .iter()
            .map(|byte| write!(f, "{:02X}", byte))
            .collect::<std::fmt::Result>()
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

impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> ObliviousPrf for KkrtOPRFSender<OT> {
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

impl<OT: ObliviousTransferSender<Msg = Block> + SemiHonest> ObliviousPrf for KkrtOPRFReceiver<OT> {
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

/// KKRT oblivious PRF sender.
pub struct KkrtOPRFSender<OT: ObliviousTransferReceiver + SemiHonest> {
    _ot: PhantomData<OT>,
    s: Vec<bool>,
    s_: [u8; 64],
    code: PseudorandomCode,
    rngs: Vec<AesRng>,
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> ObliviousPrfSender
    for KkrtOPRFSender<OT>
{
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
            s_,
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
        // Round up if necessary so that `m mod 16 ≡ 0`.
        let nrows = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        const ncols: usize = 512;
        let mut t0 = vec![0u8; nrows / 8];
        let mut t1 = vec![0u8; nrows / 8];
        let mut qs = vec![0u8; nrows * ncols / 8];
        for (j, b) in self.s.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let mut q = &mut qs[range];
            self.rngs[j].fill_bytes(&mut q);
            stream::read_bytes_inplace(reader, &mut t0)?;
            stream::read_bytes_inplace(reader, &mut t1)?;
            scutils::xor_inplace(&mut q, if *b { &t1 } else { &t0 });
        }
        let qs = utils::transpose(&qs, ncols, nrows);
        let seeds = qs
            .chunks(ncols / 8)
            .map(|q| Seed(*array_ref![q, 0, 64]))
            .collect::<Vec<Self::Seed>>();
        Ok(seeds[0..m].to_vec())
    }

    #[inline]
    fn compute(&self, seed: Self::Seed, input: Self::Input) -> Self::Output {
        let mut output = Output([0u8; 64]);
        self.code.encode(input, &mut output.0);
        scutils::and_inplace(&mut output.0, &self.s_);
        scutils::xor_inplace(&mut output.0, &seed.0);
        output
    }
}

// Separate out `encode` function for optimization purposes.
impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> KkrtOPRFSender<OT> {
    #[inline]
    pub fn encode(
        &self,
        input: <KkrtOPRFSender<OT> as ObliviousPrf>::Input,
        output: &mut <KkrtOPRFSender<OT> as ObliviousPrf>::Output,
    ) {
        self.code.encode(input, &mut output.0);
        scutils::and_inplace(&mut output.0, &self.s_);
    }
}

/// KKRT oblivious PRF receiver.
pub struct KkrtOPRFReceiver<OT: ObliviousTransferSender + SemiHonest> {
    _ot: PhantomData<OT>,
    code: PseudorandomCode,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<OT: ObliviousTransferSender<Msg = Block> + SemiHonest> ObliviousPrfReceiver
    for KkrtOPRFReceiver<OT>
{
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
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error> {
        let m = inputs.len();
        // Round up if necessary so that `m mod 16 ≡ 0`.
        let nrows = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        const ncols: usize = 512;
        let mut t0s = vec![0u8; nrows * ncols / 8];
        rng.fill_bytes(&mut t0s);
        let out = t0s
            .chunks(64)
            .map(|c| Output(*array_ref![c, 0, 64]))
            .collect::<Vec<Output>>();
        let mut t1s = t0s.clone();
        let mut c = [0u8; ncols / 8];
        for (j, r) in inputs.iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t1 = &mut t1s[range];
            self.code.encode(*r, &mut c);
            scutils::xor_inplace(&mut t1, &c);
        }
        let t0s = utils::transpose(&t0s, nrows, ncols);
        let t1s = utils::transpose(&t1s, nrows, ncols);
        let mut t = vec![0u8; nrows / 8];
        for j in 0..self.rngs.len() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t0 = &t0s[range];
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t1 = &t1s[range];
            self.rngs[j].0.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, &t0);
            stream::write_bytes(writer, &t)?;
            self.rngs[j].1.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, &t1);
            stream::write_bytes(writer, &t)?;
        }
        writer.flush()?;
        Ok(out[0..m].to_vec())
    }
}

impl<OT: ObliviousTransferReceiver<Msg = Block> + SemiHonest> SemiHonest for KkrtOPRFSender<OT> {}
impl<OT: ObliviousTransferSender<Msg = Block> + SemiHonest> SemiHonest for KkrtOPRFReceiver<OT> {}

use crate::{alsz, chou_orlandi};

/// KKRT oblivious PRF sender using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtSender = KkrtOPRFSender<alsz::AlszOTReceiver<chou_orlandi::ChouOrlandiOTSender>>;
/// KKRT oblivious PRF receiver using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtReceiver = KkrtOPRFReceiver<alsz::AlszOTSender<chou_orlandi::ChouOrlandiOTReceiver>>;

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use super::*;
    use crate::oprf::ObliviousPrfReceiver;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

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
                .zip(seeds.into_iter())
                .map(|(inp, seed)| oprf.compute(seed, *inp))
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
