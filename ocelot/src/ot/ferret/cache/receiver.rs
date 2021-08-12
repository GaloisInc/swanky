use super::VecTake;

use crate::{
    errors::Error,
    ot::{CorrelatedReceiver, RandomReceiver, Receiver as OtReceiver},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

/// A collection of correlated OT outputs
pub struct CachedReceiver {
    u: Vec<bool>,
    w: Vec<Block>,
}

impl Default for CachedReceiver {
    fn default() -> Self {
        Self {
            u: vec![],
            w: vec![],
        }
    }
}

impl CachedReceiver {
    pub fn append<I1: Iterator<Item = bool>, I2: Iterator<Item = Block>>(&mut self, u: I1, w: I2) {
        self.u.extend(u);
        self.w.extend(w);
        debug_assert_eq!(self.u.len(), self.w.len());
    }

    pub fn generate<
        OT: OtReceiver<Msg = Block> + RandomReceiver + CorrelatedReceiver,
        RNG: CryptoRng + Rng,
        C: AbstractChannel,
    >(
        &mut self,
        ot: &mut OT,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<(), Error> {
        let mut u: Vec<bool> = (0..len).map(|_| rng.gen()).collect();
        let mut w = ot.receive_random(channel, &u[..], rng)?;
        self.u.append(&mut u);
        self.w.append(&mut w);
        Ok(())
    }

    pub fn get<'a>(&'a mut self, len: usize) -> Option<(VecTake<'a, bool>, VecTake<'a, Block>)> {
        if self.capacity() < len {
            None
        } else {
            Some((
                VecTake::new(&mut self.u, len),
                VecTake::new(&mut self.w, len),
            ))
        }
    }

    pub fn capacity(&self) -> usize {
        self.u.len()
    }
}
