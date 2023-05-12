//! Implementation of the batched, related-key oblivious pseudorandom function
//! (BaRK-OPRF) protocol of Kolesnikov, Kumaresan, Rosulek, and Trieu (cf.
//! <https://eprint.iacr.org/2016/799>, Figure 2).

#![allow(non_upper_case_globals)]

use super::prc::PseudorandomCode;
use crate::{
    errors::Error,
    oprf::{ObliviousPrf, Receiver as OprfReceiver, Sender as OprfSender},
    ot::{Receiver as OtReceiver, Sender as OtSender},
    utils,
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{
    cointoss, utils as scutils, AbstractChannel, AesRng, Block, Block512, SemiHonest,
};
use std::marker::PhantomData;

/// KKRT oblivious PRF sender.
pub struct Sender<OT: OtReceiver + SemiHonest> {
    _ot: PhantomData<OT>,
    s: Vec<bool>,
    s_: [u8; 64],
    code: PseudorandomCode,
    rngs: Vec<AesRng>,
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> ObliviousPrf for Sender<OT> {
    type Seed = Block512;
    type Input = Block;
    type Output = Block512;
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OprfSender for Sender<OT> {
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        let mut ot = OT::init(channel, rng)?;
        let mut s_ = [0u8; 64];
        rng.fill_bytes(&mut s_);
        let s = utils::u8vec_to_boolvec(&s_);
        let seeds = (0..4).map(|_| rng.gen()).collect::<Vec<Block>>();
        let keys = cointoss::send(channel, &seeds)?;
        let code = PseudorandomCode::new(keys[0], keys[1], keys[2], keys[3]);
        let ks = ot.receive(channel, &s, rng)?;
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

    fn send<C, RNG>(
        &mut self,
        channel: &mut C,
        m: usize,
        _: &mut RNG,
    ) -> Result<Vec<Self::Seed>, Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    {
        // Round up if necessary so that `m mod 16 ≡ 0`.
        let nrows = if m % 16 != 0 { m + (16 - m % 16) } else { m };
        const ncols: usize = 512;
        let mut t0 = vec![0u8; nrows / 8];
        let mut t1 = vec![0u8; nrows / 8];
        let mut qs = vec![0u8; nrows * ncols / 8];
        for (j, b) in self.s.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let q = &mut qs[range];
            self.rngs[j].fill_bytes(q);
            channel.read_bytes(&mut t0)?;
            channel.read_bytes(&mut t1)?;
            scutils::xor_inplace(q, if *b { &t1 } else { &t0 });
        }
        let qs = utils::transpose(&qs, ncols, nrows);
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
pub struct Receiver<OT: OtSender + SemiHonest> {
    _ot: PhantomData<OT>,
    code: PseudorandomCode,
    rngs: Vec<(AesRng, AesRng)>,
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
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng)?;
        let seeds = (0..4).map(|_| rng.gen()).collect::<Vec<Block>>();
        let keys = cointoss::receive(channel, &seeds)?;
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
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
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
    ) -> Result<Vec<Self::Output>, Error> {
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
        let t0s = utils::transpose(&t0s, nrows, ncols);
        let t1s = utils::transpose(&t1s, nrows, ncols);
        let mut t = vec![0u8; nrows / 8];
        for j in 0..self.rngs.len() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t0 = &t0s[range];
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t1 = &t1s[range];
            self.rngs[j].0.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, t0);
            channel.write_bytes(&t)?;
            self.rngs[j].1.fill_bytes(&mut t);
            scutils::xor_inplace(&mut t, t1);
            channel.write_bytes(&t)?;
        }
        channel.flush()?;
        Ok(out[0..m].to_vec())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf;
    use scuttlebutt::{AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    #[test]
    fn test_seed() {
        let mut rng = AesRng::new();
        let mut input = [0u8; 64];
        rng.fill_bytes(&mut input);
        let seed = Block512::from(input);
        assert_eq!(seed.as_ref(), input.as_ref());
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
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut oprf = oprf::KkrtSender::init(&mut channel, &mut rng).unwrap();
            let seeds = oprf.send(&mut channel, n, &mut rng).unwrap();
            let mut results = results.lock().unwrap();
            *results = selections_
                .iter()
                .zip(seeds.into_iter())
                .map(|(inp, seed)| oprf.compute(seed, *inp))
                .collect::<Vec<Block512>>();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut oprf = oprf::KkrtReceiver::init(&mut channel, &mut rng).unwrap();
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
