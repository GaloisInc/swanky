// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementations of the table-based one-time OPPRF and the hash-based
//! multi-use OPPRF of Kolesnikov, Matania, Pinkas, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2017/799>).

use crate::errors::Error;
use crate::oprf::{Receiver as OprfReceiver, Sender as OprfSender};
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{AbstractChannel, Aes128, Block, Block512, SemiHonest};
use std::collections::HashSet;
use std::time::SystemTime;

mod cuckoo;

impl From<cuckoo::Error> for Error {
    fn from(e: cuckoo::Error) -> Error {
        Error::Other(format!("Cuckoo hash error: {}", e))
    }
}

// Number of times to iterate when creating the sender's hash table.
const N_TABLE_LOOPS: usize = 128;

// Hash `x` and `k`, producing a result in range `[0..range-1]`. We use the
// Davies-Meyer single-block-length compression function under-the-hood.
#[inline]
fn hash_input(x: Block, k: Block, range: usize) -> usize {
    let aes = Aes128::new(x);
    hash_input_keyed(&aes, k, range)
}

// Same as `hash_input`, but with a pre-keyed AES for `x`.
#[inline]
fn hash_input_keyed(x: &Aes128, k: Block, range: usize) -> usize {
    let h = x.encrypt(k) ^ k;
    (u128::from(h) % (range as u128)) as usize
}

// Hash `y`, using `k` as the hash "key", and output the result in the range
// `[0..range-1]`.
#[inline]
fn hash_output(y: &Block512, k: Block, range: usize) -> usize {
    let aes = Aes128::new(k);
    hash_output_keyed(y, &aes, range)
}

// XXX: IS THIS SECURE?!
#[inline]
fn hash_output_keyed(y: &Block512, k: &Aes128, range: usize) -> usize {
    let y: &[Block; 4] = y.into();
    let h = k.encrypt(y[0]) ^ y[0];
    let h = k.encrypt(h) ^ y[1];
    let h = k.encrypt(h) ^ y[2];
    let h = k.encrypt(h) ^ y[3];
    (u128::from(h) % (range as u128)) as usize
}

/// KMPRT oblivious programmable PRF sender for a single input value.
pub struct SingleSender<OPRF: OprfSender + SemiHonest> {
    oprf: OPRF,
}

impl<OPRF: OprfSender<Seed = Block512, Input = Block, Output = Block512> + SemiHonest>
    SingleSender<OPRF>
{
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let oprf = OPRF::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the OPPRF, with `(x, y)` values given by `points` being programmed
    /// into the PRF. The value `npoints` is an upper-bound on the length of
    /// `points`. The value `t` must be set to `1`, otherwise we return
    /// `Error::InvalidInputLength`.
    fn send<C, RNG>(
        &mut self,
        channel: &mut C,
        points: &[(Block, Block512)],
        npoints: usize,
        t: usize,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        if t != 1 {
            return Err(Error::InvalidInputLength);
        }
        // Check that all input points are unique.
        debug_assert_eq!(
            {
                let mut points = points.iter().map(|(x, _)| *x).collect::<Vec<Block>>();
                points.sort();
                points.dedup();
                points.len()
            },
            points.len()
        );
        assert!(points.len() <= npoints);
        let total = SystemTime::now();
        let start = SystemTime::now();
        let seeds = self.oprf.send(channel, 1, rng)?;
        let seed = seeds[0];
        // println!(
        //     "SingleSender :: OPRF send time: {} μs",
        //     start.elapsed().unwrap().as_micros()
        // );
        let start = SystemTime::now();
        let mut v = rng.gen::<Block>();
        let mut aes = Aes128::new(v);
        let mut map = HashSet::with_capacity(points.len());
        // Store compute `y`s and `h`s for later use.
        let mut ys = vec![Block512::default(); points.len()];
        let mut hs = vec![usize::default(); points.len()];
        let mut offset = 0;
        // Guess a size for `table` using `offset`, and then try to fill
        // `map` with points hashed into the space `[0..m-1]`. If this fails
        // (because `m` is too small), we change `offset` and try again,
        // looping until we choose an appropriate `m` such that we can find
        // a `v` such that every entry in `map` is distinct.
        let mut m = table_size(npoints, offset);
        let increment = m;
        loop {
            // Sample `v` until all values in `map` are distinct.
            for _ in 0..N_TABLE_LOOPS {
                for (i, (x, _)) in points.iter().enumerate() {
                    ys[i] = self.oprf.compute(seed, *x);
                    hs[i] = hash_output_keyed(&ys[i], &aes, m);
                    if !map.insert(hs[i]) {
                        break;
                    }
                }
                if map.len() == points.len() {
                    break;
                }
                // Try again.
                v = rng.gen::<Block>();
                aes = Aes128::new(v);
                map.clear();
            }
            if map.len() == points.len() {
                // Success! Send `m` to the receiver and exit the loop.
                channel.write_usize(m)?;
                break;
            }
            // Failure :-(. Increment `offset` and try again.
            offset += increment;
            m = table_size(npoints, offset);
        }
        // println!(
        //     "SingleSender :: init table time: {} μs",
        //     start.elapsed().unwrap().as_micros()
        // );
        let start = SystemTime::now();
        let mut table = vec![Block512::default(); m];
        // Place points in table based on the hash of their OPRF output.
        for (h, (y_, (_, y))) in hs.into_iter().zip(ys.into_iter().zip(points.iter())) {
            table[h] = *y ^ y_;
        }
        // Fill rest of table with random elements.
        for entry in table.iter_mut() {
            if *entry == Block512::default() {
                *entry = rng.gen::<Block512>();
            }
        }
        // println!(
        //     "SingleSender :: table build time: {} μs",
        //     start.elapsed().unwrap().as_micros()
        // );
        // Send `v` and `table` to the receiver.
        channel.write_block(&v)?;
        for entry in table.iter() {
            channel.write_block512(entry)?;
        }
        channel.flush()?;
        // println!(
        //     "SingleSender :: total time: {} μs",
        //     total.elapsed().unwrap().as_micros()
        // );
        Ok(())
    }
}

// Compute `2^⌈log(npoints + 1)⌉ + offset`.
fn table_size(npoints: usize, offset: usize) -> usize {
    (((npoints + 1) as f32).log2().ceil()).exp2() as usize + offset
}

/// KMPRT oblivious programmable PRF receiver for a single input value.
pub struct SingleReceiver<OPRF: OprfReceiver + SemiHonest> {
    oprf: OPRF,
}

impl<OPRF: OprfReceiver<Seed = Block512, Input = Block, Output = Block512> + SemiHonest>
    SingleReceiver<OPRF>
{
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let oprf = OPRF::init(channel, rng)?;
        Ok(Self { oprf })
    }

    fn receive<C, RNG>(
        &mut self,
        channel: &mut C,
        _npoints: usize,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Block512, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        if inputs.len() != 1 {
            return Err(Error::InvalidInputLength);
        }
        let total = SystemTime::now();
        let outputs = self.oprf.receive(channel, inputs, rng)?;
        let mut output = outputs[0];
        let m = channel.read_usize()?;
        let v = channel.read_block()?;
        let h = hash_output(&output, v, m);
        let zero = Block512::default();
        for i in 0..m {
            let entry = channel.read_block512()?;
            output ^= if i == h { entry } else { zero };
        }
        // println!(
        //     "SingleReceiver :: total time: {} μs",
        //     total.elapsed().unwrap().as_micros()
        // );
        Ok(output)
    }
}

//
// Batched OPPRF.
//

// OPPRF parameters.
#[derive(Debug)]
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

impl<T: OprfSender<Seed = Block512, Input = Block, Output = Block512> + SemiHonest> Sender<T> {
    pub fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let opprf = SingleSender::<T>::init(channel, rng)?;
        Ok(Self { opprf })
    }

    pub fn send<C, RNG>(
        &mut self,
        channel: &mut C,
        points: &[(Block, Block512)],
        _npoints: usize,
        ninputs: usize,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let start = SystemTime::now();
        let params = Parameters::new(ninputs)?;
        // Receive `hashkeys` from the receiver. These are used to fill `bins` below.
        let mut hashkeys = Vec::with_capacity(params.h1 + params.h2);
        for _ in 0..params.h1 + params.h2 {
            let h = channel.read_block()?;
            hashkeys.push(h);
        }
        // `bins` contains `m = m₁ + m₂` vectors. The first `m₁` vectors are each of
        // size `β₁`, and the second `m₂` vectors are each of size `β₂`.
        let mut bins = Vec::with_capacity(params.m1 + params.m2);
        for _ in 0..params.m1 {
            bins.push(Vec::with_capacity(params.beta1));
        }
        for _ in params.m1..params.m1 + params.m2 {
            bins.push(Vec::with_capacity(params.beta2));
        }
        let insert = |bins: &mut Vec<Vec<(Block, Block512)>>, x: &Block, y: &Block512, h: usize| {
            // Only add `(x, y)` if it is not already in the bin.
            if bins[h].iter().find(|&&entry| entry == (*x, *y)).is_none() {
                bins[h].push((*x, *y));
            }
        };
        // Place each point in the hash table, once for each hash function.
        for (x, y) in points.iter() {
            let aes = Aes128::new(*x);
            for key in hashkeys[0..params.h1].iter() {
                let h = hash_input_keyed(&aes, *key, params.m1);
                insert(&mut bins, x, y, h);
            }
            for key in hashkeys[params.h1..params.h1 + params.h2].iter() {
                let h = hash_input_keyed(&aes, *key, params.m2);
                insert(&mut bins, x, y, params.m1 + h);
            }
        }
        println!(
            "Sender :: setup time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        // Run the one-time OPPRF on each bin.
        for (j, bin) in bins.into_iter().enumerate() {
            // `beta` is the maximum number of entries a bin could have.
            let beta = if j < params.m1 {
                params.beta1
            } else {
                params.beta2
            };
            let _ = self.opprf.send(channel, &bin, beta, 1, rng)?;
        }
        println!(
            "Sender :: OPPRF send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        Ok(())
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

impl<T: OprfReceiver<Seed = Block512, Input = Block, Output = Block512> + SemiHonest> Receiver<T> {
    pub fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let opprf = SingleReceiver::<T>::init(channel, rng)?;
        Ok(Self { opprf })
    }

    pub fn receive<C, RNG>(
        &mut self,
        channel: &mut C,
        _npoints: usize,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Vec<Block512>, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore,
    {
        let start = SystemTime::now();
        let params = Parameters::new(inputs.len())?;
        let table;
        // Generate random values to be used for the hash functions. We loop,
        // trying random `hashkeys` each time until we can successfully build
        // the cuckoo hash. Once successful, we send `hashkeys` to the sender so
        // they can build their own (non-cuckoo) table.
        loop {
            let hashkeys = (0..params.h1 + params.h2)
                .map(|_| rng.gen())
                .collect::<Vec<Block>>();
            // let hashkeys = cointoss::receive(reader, writer, &seeds)?;
            // Build a cuckoo hash table using `hashkeys`.
            if let Ok(table_) = cuckoo::CuckooHash::build(
                inputs,
                &hashkeys,
                (params.m1, params.m2),
                (params.h1, params.h2),
            ) {
                table = table_;
                // Send `hashkeys` to the sender.
                for h in hashkeys.into_iter() {
                    channel.write_block(&h)?;
                }
                break;
            }
        }
        println!(
            "Receiver :: setup time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        // Run the one-time OPPRF for each table entry. For those where the
        // entry is a real input value, store the OPPRF output, otherwise use a
        // dummy value and ignore the output.
        let start = SystemTime::now();
        let mut outputs = (0..inputs.len())
            .map(|_| Default::default())
            .collect::<Vec<Block512>>();
        let n = table.items.len();
        for (j, item) in table.items.into_iter().enumerate() {
            let beta = if j < params.m1 {
                params.beta1
            } else {
                params.beta2
            };
            if let Some(item) = item {
                assert_eq!(inputs[item.index], item.entry);
                assert_eq!(outputs[item.index], Default::default());
                outputs[item.index] = self.opprf.receive(channel, beta, &[item.entry], rng)?;
            } else {
                let entry = rng.gen::<Block>();
                let _ = self.opprf.receive(channel, beta, &[entry], rng)?;
            }
        }
        println!(
            "Receiver :: OPPRF time [{}]: {} ms",
            n,
            start.elapsed().unwrap().as_millis()
        );

        Ok(outputs)
    }
}

use crate::oprf;

// XXX: Move to `oprf/mod.rs` once deemed stable enough.

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
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    fn _test_opprf_points(ninputs: usize, npoints: usize, npoints_bound: usize) {
        assert!(ninputs <= npoints);
        assert!(npoints <= npoints_bound);
        let mut rng = AesRng::new();
        let points = (0..npoints)
            .map(|_| (rng.gen::<Block>(), rng.gen()))
            .collect::<Vec<(Block, Block512)>>();
        let xs = points[0..ninputs]
            .iter()
            .map(|(x, _)| *x)
            .collect::<Vec<Block>>();
        let ys = points[0..ninputs]
            .iter()
            .map(|(_, y)| *y)
            .collect::<Vec<Block512>>();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let points_ = points.clone();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut oprf = KmprtSender::init(&mut channel, &mut rng).unwrap();
            let _ = oprf
                .send(&mut channel, &points_, npoints_bound, ninputs, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = KmprtReceiver::init(&mut channel, &mut rng).unwrap();
        let outputs = oprf
            .receive(&mut channel, npoints_bound, &xs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let mut okay = true;
        for j in 0..ninputs {
            if ys[j] != outputs[j] {
                okay = false;
            }
        }
        assert_eq!(okay, true);
    }

    #[test]
    fn test_opprf() {
        _test_opprf_points(1, 8, 8);
        _test_opprf_points(21, 48, 48);
        _test_opprf_points(163, 384, 384);
        // Settings for PSTY with `n = 2^8`.
        _test_opprf_points(326, 768, 768);
        // Settings for PSTY with `n = 2^12`.
        _test_opprf_points(5202, 12288, 12288);
        // Settings for PSTY with `n = 2^16`.
        // _test_opprf_points(83231, 196608, 196608);
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
    fn bench_hash_output(b: &mut Bencher) {
        let x = black_box(rand::random::<Block512>());
        let k = black_box(rand::random::<Block>());
        let range = 15;
        b.iter(|| super::hash_output(&x, k, range));
    }

    #[bench]
    fn bench_hash_output_keyed(b: &mut Bencher) {
        let x = black_box(rand::random::<Block512>());
        let k = black_box(rand::random::<Block>());
        let aes = Aes128::new(k);
        let range = 15;
        b.iter(|| super::hash_output_keyed(&x, &aes, range));
    }

    #[bench]
    fn bench_hash_input(b: &mut Bencher) {
        let x = black_box(rand::random::<Block>());
        let k = black_box(rand::random::<Block>());
        let range = 15;
        b.iter(|| super::hash_input(x, k, range));
    }

    #[bench]
    fn bench_hash_input_keyed(b: &mut Bencher) {
        let x = black_box(rand::random::<Block>());
        let k = black_box(rand::random::<Block>());
        let aes = Aes128::new(x);
        let range = 15;
        b.iter(|| super::hash_input_keyed(&aes, k, range));
    }
}
