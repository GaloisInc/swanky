//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};

/// Oblivious transfer sender.
pub struct Sender {
    y: Scalar,
    s: RistrettoPoint,
    counter: u128,
}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let y = Scalar::random(&mut rng);
        let s = &y * RISTRETTO_BASEPOINT_TABLE;
        channel.write_pt(&s)?;
        channel.flush()?;
        Ok(Self { y, s, counter: 0 })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let ys = self.y * self.s;
        let ks = (0..inputs.len())
            .map(|i| {
                let r = channel.read_pt()?;
                let yr = self.y * r;
                let k0 = Block::hash_pt(self.counter + i as u128, &yr);
                let k1 = Block::hash_pt(self.counter + i as u128, &(yr - ys));
                Ok((k0, k1))
            })
            .collect::<Result<Vec<(Block, Block)>, Error>>()?;
        self.counter += inputs.len() as u128;
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            channel.write_block(&c0)?;
            channel.write_block(&c1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Sender")
    }
}

/// Oblivious transfer receiver.
pub struct Receiver {
    s: RistrettoBasepointTable,
    counter: u128,
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        let s = channel.read_pt()?;
        let s = RistrettoBasepointTable::create(&s);
        Ok(Self { s, counter: 0 })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let zero = &Scalar::ZERO * &self.s;
        let one = &Scalar::ONE * &self.s;
        let ks = inputs
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Scalar::random(&mut rng);
                let c = if *b { one } else { zero };
                let r = c + &x * RISTRETTO_BASEPOINT_TABLE;
                channel.write_pt(&r)?;
                Ok(Block::hash_pt(self.counter + i as u128, &(&x * &self.s)))
            })
            .collect::<Result<Vec<Block>, Error>>()?;
        channel.flush()?;
        self.counter += inputs.len() as u128;
        inputs
            .iter()
            .zip(ks.into_iter())
            .map(|(b, k)| {
                let c0 = channel.read_block()?;
                let c1 = channel.read_block()?;
                let c = k ^ if *b { c1 } else { c0 };
                Ok(c)
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Receiver")
    }
}

impl SemiHonest for Sender {}
impl Malicious for Sender {}
impl SemiHonest for Receiver {}
impl Malicious for Receiver {}
