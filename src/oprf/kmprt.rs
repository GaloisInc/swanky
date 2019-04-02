// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use super::kkrt::{Output, Seed};
use crate::errors::Error;
use crate::oprf::{
    ObliviousPprf, ObliviousPrf, ProgrammableReceiver as OpprfReceiver,
    ProgrammableSender as OpprfSender, Receiver as OprfReceiver, Sender as OprfSender,
};
use arrayref::array_ref;
use rand::{CryptoRng, RngCore};
use scuttlebutt::utils as scutils;
use scuttlebutt::{Block, SemiHonest};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};

// Number of times to iterate when creating the sender's hash table.
const N_TABLE_LOOPS: usize = 100;

/// The oblivious programmable PRF hint.
#[derive(Clone)]
pub struct Hint(Block, Vec<Output>);

impl Hint {
    /// Generate a random hint with table size `n`.
    #[inline]
    pub fn rand<RNG: CryptoRng + RngCore>(mut rng: &mut RNG, n: usize) -> Self {
        let block = Block::rand(&mut rng);
        let table = (0..n)
            .map(|_| Output::rand(&mut rng))
            .collect::<Vec<Output>>();
        Hint(block, table)
    }
}

/// KMPRT oblivious programmable PRF sender for a single input value.
pub struct SingleSender<OPRF: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest>
{
    oprf: OPRF,
}

impl<OPRF: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPrf
    for SingleSender<OPRF>
{
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

impl<OPRF: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPprf
    for SingleSender<OPRF>
{
    type Hint = Hint;
}

impl<OPRF: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> OpprfSender
    for SingleSender<OPRF>
{
    fn init<R, W, RNG>(reader: &mut R, writer: &mut W, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let oprf = OPRF::init(reader, writer, rng)?;
        Ok(Self { oprf })
    }

    fn send<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        points: &[(Self::Input, Self::Output)],
        _: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Seed, Self::Hint)>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let npoints = points.len();
        let m = ((npoints + 1) as f32).log2().ceil().exp2() as usize;
        let mut table = (0..m).map(|_| Output::default()).collect::<Vec<Output>>();
        let seeds = self.oprf.send(reader, writer, 1, rng)?;
        let seed = seeds[0];
        let mut v = Block::rand(rng);
        let mut map = HashSet::with_capacity(npoints);
        // Sample `v` until all values in `map` are distinct.
        for _ in 0..N_TABLE_LOOPS {
            for (x, _) in points.iter() {
                let y = self.oprf.compute(seed, *x);
                let h = hash(y, v, m);
                if map.insert(h) == false {
                    break;
                }
            }
            if map.len() == npoints {
                break;
            }
            v = Block::rand(rng);
            map = HashSet::with_capacity(npoints);
        }
        if map.len() != npoints {
            return Err(Error::Other("unable to construct table".to_string()));
        }
        for (x, y) in points.iter() {
            let y_ = self.oprf.compute(seed, *x);
            let h = hash(y_, v, m);
            let entry = scutils::xor(&y_.0.to_vec(), &y.0.to_vec());
            table[h] = Output(*array_ref![entry, 0, 64]);
        }
        for entry in table.iter_mut() {
            if *entry == Output::default() {
                *entry = Output::rand(rng);
            }
        }
        v.write(writer)?;
        for entry in table.iter() {
            entry.write(writer)?;
        }
        writer.flush()?;
        let output = vec![(seed, Hint(v, table))];
        Ok(output)
    }

    #[inline]
    fn compute(&self, seed: Self::Seed, hint: Self::Hint, input: Self::Input) -> Self::Output {
        let (v, table) = (hint.0, hint.1);
        let y = self.oprf.compute(seed, input);
        let h = hash(y, v, table.len());
        let output = scutils::xor(&y.0.to_vec(), &table[h].0.to_vec());
        Output(*array_ref![output, 0, 64])
    }
}

fn hash(x: Output, v: Block, range: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.input(x);
    hasher.input(v);
    let h = hasher.result();
    let h = *array_ref![h, 0, 16];
    (u128::from_ne_bytes(h) % (range as u128)) as usize
}

/// KMPRT oblivious programmable PRF receiver for a single input value.
pub struct SingleReceiver<
    OPRF: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest,
> {
    oprf: OPRF,
}

impl<OPRF: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPrf
    for SingleReceiver<OPRF>
{
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

impl<OPRF: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPprf
    for SingleReceiver<OPRF>
{
    type Hint = Hint;
}

impl<OPRF: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> OpprfReceiver
    for SingleReceiver<OPRF>
{
    fn init<R, W, RNG>(reader: &mut R, writer: &mut W, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let oprf = OPRF::init(reader, writer, rng)?;
        Ok(Self { oprf })
    }

    fn receive<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        npoints: usize,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        if inputs.len() != 1 {
            return Err(Error::InvalidInputLength);
        }
        let m = ((npoints + 1) as f32).log2().ceil().exp2() as usize;
        let mut table = Vec::with_capacity(m);
        let outputs = self.oprf.receive(reader, writer, inputs, rng)?;
        let output = outputs[0];
        let v = Block::read(reader)?;
        let h = hash(output, v, m);
        for _ in 0..m {
            let entry = Output::read(reader)?;
            table.push(entry);
        }
        let output = scutils::xor(&table[h].0.to_vec(), &output.0.to_vec());
        let output = Output(*array_ref![output, 0, 64]);
        Ok(vec![output])
    }
}

use crate::oprf;

pub type KmprtSingleSender = SingleSender<oprf::KkrtSender>;
pub type KmprtSingleReceiver = SingleReceiver<oprf::KkrtReceiver>;

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn _test_opprf(n: usize) {
        let inputs = rand_block_vec(n);
        let inputs_ = inputs.clone();
        let results = Arc::new(Mutex::new(vec![]));
        let results_ = results.clone();
        let mut rng = AesRng::new();
        let points = (0..10)
            .map(|_| (Block::rand(&mut rng), Output::rand(&mut rng)))
            .collect::<Vec<(Block, Output)>>();
        let points_ = points.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut oprf = KmprtSingleSender::init(&mut reader, &mut writer, &mut rng).unwrap();
            let outputs = oprf
                .send(&mut reader, &mut writer, &points, n, &mut rng)
                .unwrap();
            let mut results = results.lock().unwrap();
            *results = inputs_
                .iter()
                .zip(outputs.into_iter())
                .map(|(inp, (seed, hint))| oprf.compute(seed, hint, *inp))
                .collect::<Vec<Output>>();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut oprf = KmprtSingleReceiver::init(&mut reader, &mut writer, &mut rng).unwrap();
        let outputs = oprf
            .receive(&mut reader, &mut writer, points_.len(), &inputs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let results_ = results_.lock().unwrap();
        for j in 0..n {
            assert_eq!(results_[j].0.to_vec(), outputs[j].0.to_vec());
        }
    }

    #[test]
    fn test_opprf() {
        _test_opprf(1);
    }

}
