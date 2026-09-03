#![deny(missing_docs)]
//! Implementation of the batched, related-key oblivious pseudorandom function
//! (BaRK-OPRF) protocol of Kolesnikov, Kumaresan, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2016/799>, Figure 2).

#![allow(non_upper_case_globals)]

mod prc;

use prc::PseudorandomCode;
use rand::{CryptoRng, Rng, RngExt, SeedableRng};
use std::marker::PhantomData;
use swanky_adversary::SemiHonest;
use swanky_block::{Block, Block512};
use swanky_bytearray_utils as scutils;
use swanky_channel_legacy::AbstractChannel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_oprf_traits::{ObliviousPrf, Receiver as OprfReceiver, Sender as OprfSender};
use swanky_ot_traits::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;

/// KKRT oblivious PRF sender.
pub struct Sender<OT: OtReceiver + SemiHonest = swanky_ot_alsz_kos::alsz::Receiver> {
    _ot: PhantomData<OT>,
    s: Vec<bool>,
    s_: [u8; 64],
    code: PseudorandomCode,
    rngs: Vec<SwankyRng>,
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> ObliviousPrf for Sender<OT> {
    type Seed = Block512;
    type Input = Block;
    type Output = Block512;
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OprfSender for Sender<OT> {
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        let mut ot = OT::init(channel, rng)?;
        let mut s_ = [0u8; 64];
        rng.fill_bytes(&mut s_);
        let s = swanky_deprecated_bitwise_utils::u8vec_to_boolvec(&s_);
        let seeds = (0..4).map(|_| rng.random()).collect::<Vec<Block>>();
        let keys = swanky_cointoss::send(channel, &seeds)
            .wrap_err(ErrorKind::NetworkError, "Unable to send cointoss")?;
        let code = PseudorandomCode::new(keys[0], keys[1], keys[2], keys[3]);
        let ks = ot.receive(channel, &s, rng)?;
        let rngs = ks
            .into_iter()
            .map(SwankyRng::from_seed)
            .collect::<Vec<SwankyRng>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            s,
            s_,
            code,
            rngs,
        })
    }

    fn send<C, RNG>(&mut self, channel: &mut C, m: usize, _: &mut RNG) -> Result<Vec<Self::Seed>>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        // Round up if necessary so that `m mod 16 ≡ 0`.
        let nrows = if !m.is_multiple_of(16) {
            m + (16 - m % 16)
        } else {
            m
        };
        const ncols: usize = 512;
        let mut t0 = vec![0u8; nrows / 8];
        let mut t1 = vec![0u8; nrows / 8];
        let mut qs = vec![0u8; nrows * ncols / 8];
        for (j, b) in self.s.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let q = &mut qs[range];
            self.rngs[j].fill_bytes(q);
            channel
                .read_bytes(&mut t0)
                .wrap_err(ErrorKind::NetworkError, "Unable to read bytes")?;
            channel
                .read_bytes(&mut t1)
                .wrap_err(ErrorKind::NetworkError, "Unable to read bytes")?;
            scutils::xor_inplace(q, if *b { &t1 } else { &t0 });
        }
        let qs = swanky_bit_matrix_transpose::transpose(&qs, ncols, nrows);
        let seeds = qs
            .chunks(ncols / 8)
            .map(|q| q.try_into().unwrap())
            .collect::<Vec<Self::Seed>>();
        Ok(seeds[0..m].to_vec())
    }

    fn compute(&self, seed: Self::Seed, input: Self::Input) -> Self::Output {
        let mut output = Self::Output::default();
        self.encode(input, &mut output);
        scutils::xor_inplace(output.as_mut(), seed.as_ref());
        output
    }
}

// Separate out `encode` function for optimization purposes.
impl<OT: OtReceiver<Msg = Block> + SemiHonest> Sender<OT> {
    /// Encode `input` into `output`. This is *not* the same as the `compute`
    /// method as it does not integrate the OPRF seed. However, it is useful for
    /// optimization purposes (e.g., when the same seed is used on multiple
    /// encoded inputs).
    pub fn encode(
        &self,
        input: <Sender<OT> as ObliviousPrf>::Input,
        output: &mut <Sender<OT> as ObliviousPrf>::Output,
    ) {
        self.code.encode(input, output.into());
        scutils::and_inplace(output.as_mut(), &self.s_);
    }
}

/// KKRT oblivious PRF receiver.
pub struct Receiver<OT: OtSender + SemiHonest = swanky_ot_alsz_kos::alsz::Sender> {
    _ot: PhantomData<OT>,
    code: PseudorandomCode,
    rngs: Vec<(SwankyRng, SwankyRng)>,
}

impl<OT: OtSender<Msg = Block> + SemiHonest> ObliviousPrf for Receiver<OT> {
    type Seed = Block512;
    type Input = Block;
    type Output = Block512;
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OprfReceiver for Receiver<OT> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self> {
        let mut ot = OT::init(channel, rng)?;
        let seeds = (0..4).map(|_| rng.random()).collect::<Vec<Block>>();
        let keys = swanky_cointoss::receive(channel, &seeds)
            .wrap_err(ErrorKind::NetworkError, "Unable to receive cointoss")?;
        let code = PseudorandomCode::new(keys[0], keys[1], keys[2], keys[3]);
        let mut ks = Vec::with_capacity(512);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..512 {
            rng.fill_bytes(k0.as_mut());
            rng.fill_bytes(k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(channel, &ks, rng)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (SwankyRng::from_seed(k0), SwankyRng::from_seed(k1)))
            .collect::<Vec<(SwankyRng, SwankyRng)>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            code,
            rngs,
        })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[Self::Input],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Output>> {
        let m = inputs.len();
        // Round up if necessary so that `m mod 16 ≡ 0`.
        let nrows = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        const ncols: usize = 512;
        let mut t0s = vec![0u8; nrows * ncols / 8];
        rng.fill_bytes(&mut t0s);
        let out = t0s
            .chunks(ncols / 8)
            .map(|c| c.try_into().unwrap())
            .collect::<Vec<Block512>>();
        let mut t1s = t0s.clone();
        let mut c = Block512::default();
        for (j, input) in inputs.iter().enumerate() {
            // Compute `C(input) ⊕ t_{0,j}`. Thus, `range` is a 512-bit chunk.
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let t1 = &mut t1s[range];
            self.code.encode(*input, (&mut c).into());
            scutils::xor_inplace(t1, c.as_ref());
        }
        let t0s = swanky_bit_matrix_transpose::transpose(&t0s, nrows, ncols);
        let t1s = swanky_bit_matrix_transpose::transpose(&t1s, nrows, ncols);
        let mut t = vec![0u8; nrows / 8];
        for j in 0..self.rngs.len() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t0 = &t0s[range];
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t1 = &t1s[range];
            self.rngs[j].0.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, t0);
            channel
                .write_bytes(&t)
                .wrap_err(ErrorKind::NetworkError, "Unable to write bytes")?;
            self.rngs[j].1.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, t1);
            channel
                .write_bytes(&t)
                .wrap_err(ErrorKind::NetworkError, "Unable to write bytes")?;
        }
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
        Ok(out[0..m].to_vec())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };
    use swanky_channel_legacy::Channel;
    use swanky_rng::SwankyRng;

    #[test]
    fn test_seed() {
        let mut rng = SwankyRng::new();
        let mut input = [0u8; 64];
        rng.fill_bytes(&mut input);
        let seed = Block512::from(input);
        assert_eq!(seed.as_ref(), input.as_slice());
    }

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
            let mut rng = SwankyRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut oprf =
                Sender::<swanky_ot_alsz_kos::alsz::Receiver>::init(&mut channel, &mut rng).unwrap();
            let seeds = oprf.send(&mut channel, n, &mut rng).unwrap();
            let mut results = results.lock().unwrap();
            *results = selections_
                .iter()
                .zip(seeds)
                .map(|(inp, seed)| oprf.compute(seed, *inp))
                .collect::<Vec<Block512>>();
        });
        let mut rng = SwankyRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut oprf =
            Receiver::<swanky_ot_alsz_kos::alsz::Sender>::init(&mut channel, &mut rng).unwrap();
        let outputs = oprf.receive(&mut channel, &selections, &mut rng).unwrap();
        handle.join().unwrap();
        let results_ = results_.lock().unwrap();
        for j in 0..n {
            assert_eq!(results_[j], outputs[j]);
        }
    }

    #[test]
    fn test_oprf() {
        _test_oprf(1);
        _test_oprf(8);
        _test_oprf(11);
        _test_oprf(64);
    }
}
