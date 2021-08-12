use super::VecTake;

use crate::{
    errors::Error,
    ot::{CorrelatedSender, FixedKeyInitializer, RandomSender, Sender as OtSender},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

/// A collection of correlated OT outputs
pub struct CachedSender {
    v: Vec<Block>, // cache
    delta: Block,
}

impl CachedSender {
    #[inline(always)]
    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn new(delta: Block) -> Self {
        CachedSender { v: vec![], delta }
    }

    pub fn append<I: Iterator<Item = Block>>(&mut self, m: I) {
        self.v.extend(m)
    }

    pub fn generate<
        OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender,
        RNG: CryptoRng + Rng,
        C: AbstractChannel,
    >(
        &mut self,
        ot: &mut OT,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<(), Error> {
        let cot = ot.send_random(channel, len, rng)?;
        #[cfg(debug_assertions)]
        for pair in cot.iter() {
            debug_assert_eq!(pair.0 ^ pair.1, self.delta, "base COT is not correlated");
        }
        self.v.extend(cot.into_iter().map(|v| v.0));
        Ok(())
    }

    pub fn get<'a>(&'a mut self, len: usize) -> Option<VecTake<'a, Block>> {
        if self.capacity() < len {
            None
        } else {
            Some(VecTake::new(&mut self.v, len))
        }
    }

    pub fn capacity(&self) -> usize {
        self.v.len()
    }
}
