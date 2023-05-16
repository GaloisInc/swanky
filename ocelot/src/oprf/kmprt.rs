//! Implementation of the hash-based multi-use OPPRF of Kolesnikov, Matania,
//! Pinkas, Rosulek, and Trieu (cf. <https://eprint.iacr.org/2017/799>).

use crate::{
    errors::Error,
    oprf::{Receiver as OprfReceiver, Sender as OprfSender},
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Aes128, Block, Block512, SemiHonest};
use std::collections::HashSet;

mod cuckoo;

impl From<cuckoo::Error> for Error {
    fn from(e: cuckoo::Error) -> Error {
        Error::Other(format!("Cuckoo hash error: {}", e))
    }
}

// Number of times to iterate when creating the sender's hash table.
const N_TABLE_LOOPS: usize = 128;

// Hash `x` with key `k`, producing a result in the range `[0..range-1]`. We use
// the Davies-Meyer-esque single-block-length compression function
// under-the-hood, and we pre-key `k`.
#[inline(always)]
fn hash_input_keyed(k: &Aes128, x: Block, range: usize) -> usize {
    let h = k.encrypt(x) ^ x;
    (u128::from(h) % (range as u128)) as usize
}

// Hash `y` with key `k`, producing a result in the range `[0..range-1]`.
fn hash_output(k: Block, y: Block512, range: usize) -> usize {
    let aes = Aes128::new(k);
    hash_output_keyed(&aes, y, range)
}

// Hash `y` with pre-keyed `k`. Uses a Davies-Meyer-esque hash function.
//
// XXX: can we remove this re-keying? It'll speed things up a bunch.
fn hash_output_keyed(k: &Aes128, y: Block512, range: usize) -> usize {
    let ys: [Block; 4] = y.into();
    let h = k.encrypt(ys[0]) ^ ys[0];
    let k = Aes128::new(h);
    let h = k.encrypt(ys[1]) ^ ys[1];
    let k = Aes128::new(h);
    let h = k.encrypt(ys[2]) ^ ys[2];
    let k = Aes128::new(h);
    let h = k.encrypt(ys[3]) ^ ys[3];
    (u128::from(h) % (range as u128)) as usize
}

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
pub struct Sender<OPRF> {
    oprf: OPRF,
}

impl<OPRF: OprfSender<Seed = Block512, Input = Block, Output = Block512> + SemiHonest>
    Sender<OPRF>
{
    /// Initialize the OPPRF sender.
    pub fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        let oprf = OPRF::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the OPPRF for `ninputs` inputs with the pairs given in
    /// `points` as the programmed points.
    pub fn send<C, RNG>(
        &mut self,
        channel: &mut C,
        points: &[(Block, Block512)],
        ninputs: usize,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        let params = Parameters::new(ninputs)?;
        // Receive `hashkeys` from the receiver. These are used to fill `bins` below.
        let mut hashkeys = Vec::with_capacity(params.h1 + params.h2);
        for _ in 0..params.h1 + params.h2 {
            let h = channel.read_block()?;
            let aes = Aes128::new(h);
            hashkeys.push(aes);
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

        // Place each point in the hash table, once for each hash function.
        for (x, y) in points.iter() {
            let mut hs = Vec::with_capacity(params.h1);
            for key in hashkeys[0..params.h1].iter() {
                let h = hash_input_keyed(key, *x, params.m1);
                // Only add the point if it doesn't already exist in the `h`th
                // bin.
                if !hs.iter().any(|&h_| h_ == h) {
                    bins[h].push((*x, *y));
                    hs.push(h);
                }
            }
            let mut hs = Vec::with_capacity(params.h1);
            for key in hashkeys[params.h1..params.h1 + params.h2].iter() {
                let h = hash_input_keyed(key, *x, params.m2);
                // Only add the point if it doesn't already exist in the `h`th
                // bin.
                if !hs.iter().any(|&h_| h_ == h) {
                    bins[params.m1 + h].push((*x, *y));
                    hs.push(h);
                }
            }
        }

        let seeds = self.oprf.send(channel, bins.len(), rng)?;
        // Run the one-time OPPRF on each bin.
        for (j, (bin, seed)) in bins.into_iter().zip(seeds.into_iter()).enumerate() {
            // `beta` is the maximum number of entries a bin could have.
            let beta = if j < params.m1 {
                params.beta1
            } else {
                params.beta2
            };

            self.process_oprf_output(channel, seed, bin, beta, rng)?;
        }
        Ok(())
    }

    fn process_oprf_output<C, RNG>(
        &mut self,
        channel: &mut C,
        seed: Block512,
        points: Vec<(Block, Block512)>,
        npoints: usize,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
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

        let mut v = rng.gen::<Block>();
        let mut aes = Aes128::new(v);
        let mut map = HashSet::with_capacity(points.len());
        // Store compute `y`s and `h`s for later use.
        let mut ys = vec![Block512::default(); points.len()];
        let mut hs = vec![usize::default(); points.len()];
        // Guess a size for `table` using `offset`, and then try to fill
        // `map` with points hashed into the space `[0..m-1]`. If this fails
        // (because `m` is too small), we change `offset` and try again,
        // looping until we choose an appropriate `m` such that we can find
        // a `v` such that every entry in `map` is distinct.
        //
        // Note that choosing `m` correctly quickly matters **a lot** to the
        // overall running time.
        let mut m = Self::table_size(npoints);
        let increment = m;
        loop {
            // Sample `v` until all values in `map` are distinct.
            for _ in 0..N_TABLE_LOOPS {
                for (i, (x, _)) in points.iter().enumerate() {
                    ys[i] = self.oprf.compute(seed, *x);
                    hs[i] = hash_output_keyed(&aes, ys[i], m);
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
            m += increment;
        }
        let mut table = vec![Block512::default(); m];
        // Place points in table based on the hash of their OPRF output.
        for (h, (y_, (_, y))) in hs.into_iter().zip(ys.into_iter().zip(points.into_iter())) {
            table[h] = y ^ y_;
        }
        // Fill rest of table with random elements.
        for entry in table.iter_mut() {
            if *entry == Block512::default() {
                *entry = rng.gen::<Block512>();
            }
        }
        // Send `v` and `table` to the receiver.
        channel.write_block(&v)?;
        for entry in table.iter() {
            channel.write_block512(entry)?;
        }
        channel.flush()?;
        Ok(())
    }

    // Compute the table size for the OPPRF.
    #[inline(always)]
    fn table_size(npoints: usize) -> usize {
        // These are over-approximations, but appear to lead to better running
        // times (at the expense of more communication).
        if npoints <= 32 {
            32
        } else if npoints <= 64 {
            256
        } else {
            (((npoints + 2) as f32).log2().ceil()).exp2() as usize
        }
    }
}

/// KMPRT oblivious programmable PRF receiver.
///
/// This implements the hashing-based OPPRF receiver in Figure 7 of the paper. It
/// uses the table-based one-time OPPRF under-the-hood (Figure 6 of the paper),
/// which itself uses an OPRF.
pub struct Receiver<OPRF: OprfReceiver + SemiHonest> {
    oprf: OPRF,
}

impl<OPRF: OprfReceiver<Seed = Block512, Input = Block, Output = Block512> + SemiHonest>
    Receiver<OPRF>
{
    /// Initialize the OPPRF receiver.
    pub fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        let oprf = OPRF::init(channel, rng)?;
        Ok(Self { oprf })
    }

    /// Run the OPPRF on inputs provided by the `inputs` slice.
    pub fn receive<C, RNG>(
        &mut self,
        channel: &mut C,
        inputs: &[Block],
        rng: &mut RNG,
    ) -> Result<Vec<Block512>, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
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
                channel.flush()?;
                break;
            }
        }

        let mut outputs = (0..inputs.len())
            .map(|_| Default::default())
            .collect::<Vec<Block512>>();

        let items = table
            .items
            .iter()
            .map(|item| {
                if let Some(item) = item {
                    item.entry
                } else {
                    rng.gen::<Block>()
                }
            })
            .collect::<Vec<Block>>();
        let oprf_outputs = self.oprf.receive(channel, &items, rng)?;

        let zero = Block512::default();
        for (item, output) in table.items.into_iter().zip(oprf_outputs.into_iter()) {
            let m = channel.read_usize()?;
            let v = channel.read_block()?;
            let h = hash_output(v, output, m);
            let mut output = output;
            for i in 0..m {
                let entry = channel.read_block512()?;
                output ^= if i == h { entry } else { zero };
            }
            if let Some(item) = item {
                outputs[item.index] = output;
            }
        }
        Ok(outputs)
    }
}

//
// Tests.
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf::{KmprtReceiver, KmprtSender};
    use scuttlebutt::{AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

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
                .send(&mut channel, &points_, ninputs, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = KmprtReceiver::init(&mut channel, &mut rng).unwrap();
        let outputs = oprf.receive(&mut channel, &xs, &mut rng).unwrap();
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
        // _test_opprf_points(5202, 12288, 12288);
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
        let k = black_box(rand::random::<Block>());
        let x = black_box(rand::random::<Block512>());
        let range = 15;
        b.iter(|| super::hash_output(k, x, range));
    }

    #[bench]
    fn bench_hash_output_keyed(b: &mut Bencher) {
        let k = black_box(rand::random::<Block>());
        let x = black_box(rand::random::<Block512>());
        let aes = Aes128::new(k);
        let range = 15;
        b.iter(|| super::hash_output_keyed(&aes, x, range));
    }

    #[bench]
    fn bench_hash_input_keyed(b: &mut Bencher) {
        let k = black_box(rand::random::<Block>());
        let x = black_box(rand::random::<Block>());
        let aes = Aes128::new(k);
        let range = 15;
        b.iter(|| super::hash_input_keyed(&aes, x, range));
    }
}
