use super::*;
use crate::ot::{FixedKeyInitializer, KosDeltaSender};

use crate::Error;
use scuttlebutt::{AbstractChannel, AesHash, Block};

use rand::{CryptoRng, Rng};

use cache::CachedSender;

pub struct Sender<const REG: bool> {
    hash: AesHash,
    cots: cache::CachedSender,
    spcot: spcot::Sender,
}

impl<const REG: bool> FixedKeyInitializer for Sender<REG> {
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Self::init(s.into(), channel, rng)
    }
}

impl<const REG: bool> Sender<REG> {
    pub fn init<C: AbstractChannel, R: Rng + CryptoRng>(
        delta: Block,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Self, Error> {
        // obtain base-COT using KOS18
        let mut cots = CachedSender::new(delta);
        let mut kos18 = KosDeltaSender::init_fixed_key(channel, delta.into(), rng)?;
        cots.generate(
            &mut kos18,
            channel,
            rng,
            ferret::Sender::<REG>::cots_setup(),
        )?;

        // do 1-time setup iteration
        let mut spcot = spcot::Sender::init(delta);
        let y = ferret::Sender::<REG>::extend_setup(&mut cots, &mut spcot, rng, channel)?;
        cots.append(y.into_iter());

        // ready for main iterations
        Ok(Self {
            hash: cr_cot_hash(),
            spcot,
            cots,
        })
    }

    /// Return a random correlated OT
    pub fn cot<C: AbstractChannel, R: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Block, Error> {
        if self.cots.capacity() == ferret::Sender::<REG>::cots_main() {
            // replenish using main iteration
            let y =
                ferret::Sender::<REG>::extend_main(&mut self.cots, &mut self.spcot, rng, channel)?;
            self.cots.append(y.into_iter());
        }

        Ok(self.cots.pop().unwrap())
    }

    /// Return a random OT
    pub fn rot<C: AbstractChannel, R: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<(Block, Block), Error> {
        let cot = self.cot(channel, rng)?;
        Ok((
            cot,
            self.hash.cr_hash(Block::default(), cot ^ self.spcot.delta),
        ))
    }
}
