//! Implementation of an **entirely insecure** oblivious transfer protocol for
//! testing purposes.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = channel.read_bool()?;
            bs.push(b);
        }
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            let m = if b { m.1 } else { m.0 };
            channel.write_block(&m)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Dummy Sender")
    }
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        for b in inputs.iter() {
            channel.write_bool(*b)?;
        }
        channel.flush()?;
        let mut out = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let m = channel.read_block()?;
            out.push(m);
        }
        Ok(out)
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Dummy Receiver")
    }
}
