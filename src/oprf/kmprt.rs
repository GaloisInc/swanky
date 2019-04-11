// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementations of the tabled-based one-time OPPRF and the hash-based
//! multi-use OPPRF of Kolesnikov, Matania, Pinkas, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2017/799>).

use super::kkrt::{Output, Seed};
use crate::errors::Error;
use crate::oprf::{
    ObliviousPprf, ObliviousPrf, ProgrammableReceiver as OpprfReceiver,
    ProgrammableSender as OpprfSender, Receiver as OprfReceiver, Sender as OprfSender,
};
use arrayref::array_ref;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{cointoss, Block, SemiHonest};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};

mod cuckoo;

impl From<cuckoo::Error> for Error {
    fn from(e: cuckoo::Error) -> Error {
        Error::Other(format!("Cuckoo hash error: {}", e))
    }
}

// Number of times to iterate when creating the sender's hash table.
const N_TABLE_LOOPS: usize = 1000;

// Hash `x`, using `key` as the hash "key", and output the result in the range
// `[0..range]`.
fn hash<T>(x: T, key: Block, range: usize) -> usize
where
    T: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    hasher.input(x);
    hasher.input(key);
    let h = hasher.result();
    let h = *array_ref![h, 0, 16];
    (u128::from_ne_bytes(h) % (range as u128)) as usize
}

/// The oblivious programmable PRF hint.
#[derive(Clone)]
pub struct Hint(Block, Vec<Output>);

impl Hint {
    /// Generate a random hint with table size `n`.
    #[inline]
    pub fn rand<RNG: CryptoRng + RngCore>(rng: &mut RNG, n: usize) -> Self {
        let block = rng.gen::<Block>();
        let table = (0..n).map(|_| rng.gen::<Output>()).collect::<Vec<Output>>();
        Hint(block, table)
    }
}

/// KMPRT oblivious programmable PRF sender for a single input value.
pub struct SingleSender<OPRF: OprfSender + SemiHonest> {
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

    /// Run the OPPRF, with `(x, y)` values given by `points` being programmed
    /// into the PRF. The value `npoints` is an upper-bound on the length of
    /// `points`. The value `t` must be set to `1`, otherwise we return
    /// `Error::InvalidInputLength`.
    ///
    /// Note that `npoints` often needs to be much larger than the length of
    /// `points`, as otherwise the sender won't be able to uniquely map the `x`
    /// values. If this is the case, we return `Error::Other`.
    fn send<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        points: &[(Self::Input, Self::Output)],
        npoints: usize,
        t: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Seed, Self::Hint)>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        if t != 1 {
            return Err(Error::InvalidInputLength);
        }
        debug_assert_eq!(
            {
                let mut inputs = points.iter().map(|(x, _)| *x).collect::<Vec<Self::Input>>();
                inputs.sort();
                inputs.dedup();
                inputs.len()
            },
            points.len()
        );
        let m = table_size(npoints);
        let mut table = (0..m).map(|_| Output::default()).collect::<Vec<Output>>();
        let seeds = self.oprf.send(reader, writer, 1, rng)?;
        let seed = seeds[0];
        let mut v = rng.gen::<Block>();
        let mut map = HashSet::with_capacity(points.len());
        // Sample `v` until all values in `map` are distinct.
        for _ in 0..N_TABLE_LOOPS {
            for (x, _) in points.iter() {
                let y = self.oprf.compute(seed, *x);
                let h = hash(y, v, m);
                if !map.insert(h) {
                    break;
                }
            }
            if map.len() == points.len() {
                break;
            } else {
                v = rng.gen::<Block>();
                map.clear();
            }
        }
        if map.len() != points.len() {
            // XXX: return a better error than `Error::Other`.
            return Err(Error::Other(format!(
                "unable to construct table after {} iterations",
                N_TABLE_LOOPS
            )));
        }
        // Place points in table based on the hash of their OPRF output.
        for (x, y) in points.iter() {
            let y_ = self.oprf.compute(seed, *x);
            let h = hash(y_, v, m);
            table[h] = *y ^ y_;
        }
        // Fill rest of table with random elements.
        for entry in table.iter_mut() {
            if *entry == Output::default() {
                *entry = rng.gen::<Output>();
            }
        }
        // Write `v` and `table` to the receiver.
        v.write(writer)?;
        for entry in table.iter() {
            entry.write(writer)?;
        }
        writer.flush()?;
        let hint = Hint(v, table);
        let output = vec![(seed, hint)];
        Ok(output)
    }

    #[inline]
    fn compute(&self, seed: &Self::Seed, hint: &Self::Hint, input: &Self::Input) -> Self::Output {
        let (v, table) = (&hint.0, &hint.1);
        let y = self.oprf.compute(*seed, *input);
        let h = hash(y, *v, table.len());
        y ^ table[h]
    }
}

/// KMPRT oblivious programmable PRF receiver for a single input value.
pub struct SingleReceiver<OPRF: OprfReceiver + SemiHonest> {
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
        let m = table_size(npoints);
        let mut outputs = self.oprf.receive(reader, writer, inputs, rng)?;
        let v = Block::read(reader)?;
        let h = hash(outputs[0], v, m);
        let zero = Output::zero();
        for i in 0..m {
            let entry = Output::read(reader)?;
            outputs[0] ^= if i == h { entry } else { zero };
        }
        Ok(outputs)
    }
}

fn table_size(npoints: usize) -> usize {
    // NOTE: KMPRT gives `npoints + 1` here, but we use `+ 2` as otherwise we
    // can reach states where the table size is too small.
    (((npoints + 2) as f32).log2().ceil() + 1.0).exp2() as usize
}

//
// Batched OPPRF.
//

// OPPRF parameters.
struct Parameters {
    // The length of the "first" cuckoo hash table.
    m1: usize,
    // The length of the "second" cuckoo hash table.
    m2: usize,
    // The max bin size of the sender's "first" simple hash table.
    beta1: usize,
    // The max bin size of the sender's "second" simple hash table.
    beta2: usize,
    // The number of hashes used in the first hash table.
    h1: usize,
    // The number of hashes used in the second hash table.
    h2: usize,
}

impl Parameters {
    pub fn new(n: usize) -> Result<Self, Error> {
        let (m1, m2, beta1, beta2, h1, h2) = if n <= 1 << 12 {
            (1.17, 0.15, 27, 63, 3, 2)
        } else if n <= 1 << 14 {
            (1.15, 0.16, 28, 63, 3, 2)
        } else if n <= 1 << 16 {
            (1.14, 0.16, 29, 63, 3, 2)
        } else if n <= 1 << 20 {
            (1.13, 0.17, 30, 63, 3, 2)
        } else if n <= 1 << 24 {
            (1.12, 0.17, 31, 63, 3, 2)
        } else {
            return Err(Error::InvalidInputLength);
        };
        let m1 = ((n as f32) * m1).ceil() as usize;
        let m2 = ((n as f32) * m2).ceil() as usize;
        Ok(Self {
            m1,
            m2,
            beta1,
            beta2,
            h1,
            h2,
        })
    }
}

/// KMPRT hashing-based OPPRF sender.
///
/// This implements the hashing-based OPPRF sender in Figure 7 of the paper. It
/// uses the table-based one-time OPPRF under-the-hood (Figure 6 of the paper),
/// which itself uses an OPRF.
pub struct Sender<T: OprfSender + SemiHonest> {
    opprf: SingleSender<T>,
}

impl<T: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPrf
    for Sender<T>
{
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

impl<T: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPprf
    for Sender<T>
{
    type Hint = Hint;
}

impl<T: OprfSender<Seed = Seed, Input = Block, Output = Output> + SemiHonest> OpprfSender
    for Sender<T>
{
    fn init<R, W, RNG>(reader: &mut R, writer: &mut W, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let opprf = SingleSender::<T>::init(reader, writer, rng)?;
        Ok(Self { opprf })
    }

    fn send<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        points: &[(Self::Input, Self::Output)],
        _: usize,
        ninputs: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Seed, Self::Hint)>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let params = Parameters::new(ninputs)?;
        // Generate random values to be used for the hash functions.
        let seeds = (0..params.h1 + params.h2)
            .map(|_| rng.gen::<Block>())
            .collect::<Vec<Block>>();
        let hashkeys = cointoss::send(reader, writer, &seeds)?;

        let mut bins = Vec::with_capacity(params.m1 + params.m2);
        for _ in 0..params.m1 {
            bins.push(Vec::with_capacity(params.beta1));
        }
        for _ in params.m1..params.m1 + params.m2 {
            bins.push(Vec::with_capacity(params.beta2));
        }
        // Place each point in the hash table, once for each hash function.
        for (x, y) in points.iter() {
            for key in hashkeys[0..params.h1].iter() {
                let h = hash(*x, *key, params.m1);
                if bins[h].iter().find(|&&entry| entry == (*x, *y)).is_none() {
                    bins[h].push((*x, *y));
                }
            }
            for key in hashkeys[params.h1..params.h1 + params.h2].iter() {
                let h = hash(*x, *key, params.m2);
                if bins[params.m1 + h]
                    .iter()
                    .find(|&&entry| entry == (*x, *y))
                    .is_none()
                {
                    bins[params.m1 + h].push((*x, *y));
                }
            }
        }
        // Run the one-time OPPRF on each bin.
        let mut outputs = Vec::with_capacity(params.m1 + params.m2);
        for (j, bin) in bins.into_iter().enumerate() {
            // `beta` is the maximum number of entries a bin could have.
            let beta = if j < params.m1 {
                params.beta1
            } else {
                params.beta2
            };
            let output = self.opprf.send(reader, writer, &bin, beta, 1, rng)?;
            outputs.push(output);
        }
        // XXX: this returns `m1 + m2` (seed, hint) pairs. But there doesn't
        // really seem to be a way to *use* this when computing the OPPRF.
        // Namely, this doesn't jive with the OPPRF API as specified in Figure 3
        // of the paper. I believe this is okay in how its used to build PSI
        // (namely, the `compute` method is never used).
        Ok(outputs.into_iter().flatten().collect())
    }

    #[inline]
    fn compute(&self, _: &Self::Seed, _: &Self::Hint, _: &Self::Input) -> Self::Output {
        // This method doesn't work for the hash-based batched OPPRF, so let's panic for now.
        // self.opprf.compute(seed, hint, input)
        unimplemented!()
    }
}

/// KMPRT oblivious programmable PRF receiver.
///
/// This implements the hashing-based OPPRF receiver in Figure 7 of the paper. It
/// uses the table-based one-time OPPRF under-the-hood (Figure 6 of the paper),
/// which itself uses an OPRF.
pub struct Receiver<T: OprfReceiver + SemiHonest> {
    opprf: SingleReceiver<T>,
}

impl<T: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPrf
    for Receiver<T>
{
    type Seed = Seed;
    type Input = Block;
    type Output = Output;
}

impl<T: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> ObliviousPprf
    for Receiver<T>
{
    type Hint = Hint;
}

impl<T: OprfReceiver<Seed = Seed, Input = Block, Output = Output> + SemiHonest> OpprfReceiver
    for Receiver<T>
{
    fn init<R, W, RNG>(reader: &mut R, writer: &mut W, rng: &mut RNG) -> Result<Self, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let opprf = SingleReceiver::<T>::init(reader, writer, rng)?;
        Ok(Self { opprf })
    }

    fn receive<R, W, RNG>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        _: usize,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>, Error>
    where
        R: Read + Send,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
    {
        let params = Parameters::new(inputs.len())?;
        // Generate random values to be used for the hash functions.
        let seeds = (0..params.h1 + params.h2)
            .map(|_| rng.gen::<Block>())
            .collect::<Vec<Block>>();
        let hashkeys = cointoss::receive(reader, writer, &seeds)?;
        // Build a cuckoo hash table using `hashkeys`.
        let table = cuckoo::CuckooHash::build(
            inputs,
            &hashkeys,
            (params.m1, params.m2),
            (params.h1, params.h2),
        )?;
        let mut outputs = (0..inputs.len())
            .map(|_| Output::default())
            .collect::<Vec<Output>>();
        // Run the one-time OPPRF for each table entry. For those where the
        // entry is a real input value, store the OPPRF output, otherwise use a
        // dummy value and ignore the output.
        for (j, (item, idx, _)) in table.items.into_iter().enumerate() {
            let beta = if j < params.m1 {
                params.beta1
            } else {
                params.beta2
            };
            if let Some(item) = item {
                let idx = idx.unwrap();
                assert_eq!(inputs[idx], item);
                let out = self.opprf.receive(reader, writer, beta, &[item], rng)?;
                assert_eq!(outputs[idx], Output::default());
                outputs[idx] = out[0];
            } else {
                let item = rng.gen::<Block>();
                let _ = self.opprf.receive(reader, writer, beta, &[item], rng)?;
            }
        }
        Ok(outputs)
    }
}

use crate::oprf;

/// Instantiation of the KMPRT one-time OPPRF sender, using KKRT as the
/// underlying OPRF.
pub type KmprtSingleSender = SingleSender<oprf::KkrtSender>;
/// Instantiation of the KMPRT one-time OPPRF receiver, using KKRT as the
/// underlying OPRF.
pub type KmprtSingleReceiver = SingleReceiver<oprf::KkrtReceiver>;
/// Instantiation of the KMPRT hash-based OPPRF sender, using KKRT as the
/// underlying OPRF.
pub type KmprtSender = Sender<oprf::KkrtSender>;
/// Instantiation of the KMPRT hash-based OPPRF receiver, using KKRT as the
/// underlying OPRF.
pub type KmprtReceiver = Receiver<oprf::KkrtReceiver>;

//
// Tests.
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf::{ProgrammableReceiver, ProgrammableSender};
    use scuttlebutt::AesRng;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn _test_opprf<
        S: ProgrammableSender<Seed = Seed, Input = Block, Output = Output>,
        R: ProgrammableReceiver<Seed = Seed, Input = Block, Output = Output>,
    >(
        ninputs: usize,
        npoints: usize,
    ) {
        let inputs = rand_block_vec(ninputs);
        let inputs_ = inputs.clone();
        let results = Arc::new(Mutex::new(vec![]));
        let results_ = results.clone();
        let mut rng = AesRng::new();
        let points = (0..npoints)
            .map(|_| (rng.gen::<Block>(), rng.gen::<Output>()))
            .collect::<Vec<(Block, Output)>>();
        // let points_ = points.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let mut reader = BufReader::new(sender.try_clone().unwrap());
            let mut writer = BufWriter::new(sender);
            let mut oprf = S::init(&mut reader, &mut writer, &mut rng).unwrap();
            let outputs = oprf
                .send(
                    &mut reader,
                    &mut writer,
                    &points,
                    npoints,
                    ninputs,
                    &mut rng,
                )
                .unwrap();
            let mut results = results.lock().unwrap();
            *results = inputs_
                .iter()
                .zip(outputs.iter())
                .map(|(inp, (seed, hint))| oprf.compute(seed, hint, inp))
                .collect::<Vec<Output>>();
        });
        let mut rng = AesRng::new();
        let mut reader = BufReader::new(receiver.try_clone().unwrap());
        let mut writer = BufWriter::new(receiver);
        let mut oprf = R::init(&mut reader, &mut writer, &mut rng).unwrap();
        // let inputs = points_.iter().map(|(x, _)| *x).collect::<Vec<Block>>();
        let outputs = oprf
            .receive(&mut reader, &mut writer, npoints, &inputs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let results_ = results_.lock().unwrap();
        for j in 0..ninputs {
            assert_eq!(results_[j], outputs[j]);
        }
    }

    #[test]
    fn test_opprf() {
        _test_opprf::<KmprtSingleSender, KmprtSingleReceiver>(1, 8);
        // _test_opprf::<KmprtSender, KmprtReceiver>(8, 8);
    }

}

//
// Benchmarks.
//

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_hash(b: &mut Bencher) {
        let x = black_box(rand::random::<Block>());
        let v = black_box(rand::random::<Block>());
        let range = 15;
        b.iter(|| super::hash(x, v, range));
    }

}
