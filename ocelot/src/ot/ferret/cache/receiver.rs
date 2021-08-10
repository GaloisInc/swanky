use super::VecTake;

use crate::{
    errors::Error,
    ot::{CorrelatedReceiver, RandomReceiver, Receiver as OtReceiver},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

/// A collection of correlated OT outputs
pub struct CachedReceiver<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> {
    base: OT,
    u: Vec<bool>,
    w: Vec<Block>,
}

impl<OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver> CachedReceiver<OT> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            base: OT::init(channel, rng)?,
            u: vec![],
            w: vec![],
        })
    }

    pub fn append<I1: Iterator<Item = bool>, I2: Iterator<Item = Block>>(&mut self, u: I1, w: I2) {
        self.u.extend(u);
        self.w.extend(w);
        debug_assert_eq!(self.u.len(), self.w.len());
    }

    pub fn recv<'a, C: AbstractChannel, RNG: CryptoRng + Rng>(
        &'a mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<(VecTake<'a, bool>, VecTake<'a, Block>), Error> {
        let capacity = self.capacity();
        if capacity < len {
            // need to invoke base COT
            let mut u: Vec<bool> = (0..(len - capacity)).map(|_| rng.gen()).collect();
            let mut w = self.base.receive_random(channel, &u[..], rng)?;
            self.u.append(&mut u);
            self.w.append(&mut w);
        }
        Ok((
            VecTake::new(&mut self.u, len),
            VecTake::new(&mut self.w, len),
        ))
    }

    pub fn capacity(&self) -> usize {
        self.u.len()
    }
}
