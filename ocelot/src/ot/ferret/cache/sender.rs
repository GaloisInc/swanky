use super::VecTake;

use crate::{
    errors::Error,
    ot::{CorrelatedSender, FixedKeyInitializer, RandomSender, Sender as OtSender},
};

use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block};

/// A collection of correlated OT outputs
pub struct CachedSender<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender> {
    v: Vec<Block>, // cache
    base: OT,
    delta: Block,
}

impl<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender + FixedKeyInitializer>
    CachedSender<OT>
{
    pub fn init_delta<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        delta: Block,
    ) -> Result<Self, Error> {
        Ok(Self {
            base: OT::init_fixed_key(channel, delta.into(), rng)?,
            delta,
            v: Vec::with_capacity(1024),
        })
    }

    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let block = rng.gen();
        Self::init_delta(channel, rng, block)
    }
}

impl<OT: OtSender<Msg = Block> + RandomSender + CorrelatedSender> CachedSender<OT> {
    #[inline(always)]
    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn append<I: Iterator<Item = Block>>(&mut self, m: I) {
        self.v.extend(m)
    }

    pub fn send<'a, C: AbstractChannel, RNG: CryptoRng + Rng>(
        &'a mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: usize,
    ) -> Result<VecTake<'a, Block>, Error> {
        let capacity = self.capacity();
        if capacity < len {
            let cot = self.base.send_random(channel, len - capacity, rng)?;
            #[cfg(debug_assertions)]
            for pair in cot.iter() {
                debug_assert_eq!(pair.0 ^ pair.1, self.delta, "base COT is not correlated");
            }
            self.v.extend(cot.into_iter().map(|v| v.0))
        }
        Ok(VecTake::new(&mut self.v, len))
    }

    pub fn capacity(&self) -> usize {
        self.v.len()
    }
}
