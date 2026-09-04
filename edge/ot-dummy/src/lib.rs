#![deny(missing_docs)]
//! Implementation of an insecure OT protocol for testing purposes

use rand::CryptoRng;
use swanky_block::Block;
use swanky_channel_legacy::AbstractChannel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_ot_traits::{Receiver as OtReceiver, Sender as OtSender};

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng>(_: &mut C, _: &mut RNG) -> Result<Self> {
        Ok(Self {})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<()> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = channel
                .read_bool()
                .wrap_err(ErrorKind::NetworkError, "Unable to read bool")?;
            bs.push(b);
        }
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            let m = if b { m.1 } else { m.0 };
            channel
                .write_block(&m)
                .wrap_err(ErrorKind::NetworkError, "Unable to write block")?;
        }
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
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

    fn init<C: AbstractChannel, RNG: CryptoRng>(_: &mut C, _: &mut RNG) -> Result<Self> {
        Ok(Self {})
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Block>> {
        for b in inputs.iter() {
            channel
                .write_bool(*b)
                .wrap_err(ErrorKind::NetworkError, "Unable to write bool")?;
        }
        channel
            .flush()
            .wrap_err(ErrorKind::NetworkError, "Unable to flush channel")?;
        let mut out = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let m = channel
                .read_block()
                .wrap_err(ErrorKind::NetworkError, "Unable to read block")?;
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

#[test]
fn test_functionality() {
    swanky_ot_test::test_otext::<Sender, Receiver>(128);
}
