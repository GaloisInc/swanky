use super::*;
use crate::ot::{KosDeltaReceiver, Receiver as OtReceiver};

use crate::Error;
use scuttlebutt::{AbstractChannel, AesHash, Block};

use rand::{CryptoRng, Rng};

use cache::CachedReceiver;

pub struct Receiver<const REG: bool> {
    hash: AesHash,
    cots: cache::CachedReceiver,
    spcot: spcot::Receiver,
}

impl<const REG: bool> Receiver<REG> {
    pub fn init<C: AbstractChannel, R: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Self, Error> {
        // obtain base-COT using KOS18
        let mut cots = CachedReceiver::default();
        let mut kos18 = KosDeltaReceiver::init(channel, rng)?;
        cots.generate(
            &mut kos18,
            channel,
            rng,
            ferret::Receiver::<REG>::cots_setup(),
        )?;

        // do 1-time setup iteration
        let mut spcot = spcot::Receiver::init();
        let (x, z) = ferret::Receiver::<REG>::extend_setup(&mut cots, &mut spcot, rng, channel)?;
        cots.append(x.into_iter(), z.into_iter());

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
    ) -> Result<(bool, Block), Error> {
        // regular error
        if self.cots.capacity() == ferret::Receiver::<REG>::cots_main() {
            // replenish using main iteration
            let (x, z) = ferret::Receiver::<REG>::extend_main(
                &mut self.cots,
                &mut self.spcot,
                rng,
                channel,
            )?;
            self.cots.append(x.into_iter(), z.into_iter());
        }
        Ok(self.cots.pop().unwrap())
    }

    /// Return a random OT
    pub fn rot<C: AbstractChannel, R: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<(bool, Block), Error> {
        let (sel, output) = self.cot(channel, rng)?;
        if sel {
            Ok((true, self.hash.cr_hash(Block::default(), output)))
        } else {
            Ok((false, output))
        }
    }
}
