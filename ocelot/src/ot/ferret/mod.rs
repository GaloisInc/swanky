// mod ferret;
pub(crate) mod cache;
pub(crate) mod ferret;
pub(crate) mod lpn;
pub(crate) mod mpcot;
pub(crate) mod spcot;
pub(crate) mod util;

use crate::ot::{FixedKeyInitializer, KosDeltaReceiver, KosDeltaSender, Receiver as OtReceiver};

use crate::Error;
use scuttlebutt::{AbstractChannel, Block};

use rand::{CryptoRng, Rng};

use cache::{CachedReceiver, CachedSender};

// The computational security parameter: \kappa in the paper.
const CSP: usize = 128;

pub struct Sender {
    cots: cache::CachedSender,
    spcot: spcot::Sender,
}

pub struct Receiver {
    cots: cache::CachedReceiver,
    spcot: spcot::Receiver,
}

impl Sender {
    pub fn init<C: AbstractChannel, R: Rng + CryptoRng>(
        delta: Block,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Self, Error> {
        // obtain base-COT using KOS18
        let mut cots = CachedSender::new(delta);
        let mut kos18 = KosDeltaSender::init_fixed_key(channel, delta.into(), rng)?;
        cots.generate(&mut kos18, channel, rng, ferret::SETUP_COTS)?;

        // do 1-time setup
        let mut spcot = spcot::Sender::init(delta);
        let y = ferret::Sender::extend_setup(&mut cots, &mut spcot, rng, channel)?;
        cots.append(y.into_iter());
        debug_assert!(cots.capacity() >= ferret::MAIN_COTS);

        // ready for main iterations
        Ok(Self { spcot, cots })
    }

    pub fn cot<C: AbstractChannel, R: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Block, Error> {
        debug_assert!(self.cots.capacity() >= ferret::MAIN_COTS);
        if self.cots.capacity() == ferret::MAIN_COTS {
            // replenish using main iteration
            let y = ferret::Sender::extend_main(&mut self.cots, &mut self.spcot, rng, channel)?;
            self.cots.append(y.into_iter());
        }
        Ok(self.cots.pop().unwrap())
    }
}

impl Receiver {
    pub fn init<C: AbstractChannel, R: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut R,
    ) -> Result<Self, Error> {
        // obtain base-COT using KOS18
        let mut cots = CachedReceiver::default();
        let mut kos18 = KosDeltaReceiver::init(channel, rng)?;
        cots.generate(&mut kos18, channel, rng, ferret::SETUP_COTS)?;

        // do 1-time setup
        let mut spcot = spcot::Receiver::init();
        let (x, z) = ferret::Receiver::extend_setup(&mut cots, &mut spcot, rng, channel)?;
        cots.append(x.into_iter(), z.into_iter());
        debug_assert!(cots.capacity() >= ferret::MAIN_COTS);

        // ready for main iterations
        Ok(Self { spcot, cots })
    }

    pub fn cot<C: AbstractChannel, R: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<(bool, Block), Error> {
        debug_assert!(self.cots.capacity() >= ferret::MAIN_COTS);
        if self.cots.capacity() == ferret::MAIN_COTS {
            // replenish using main iteration
            let (x, z) =
                ferret::Receiver::extend_main(&mut self.cots, &mut self.spcot, rng, channel)?;
            self.cots.append(x.into_iter(), z.into_iter());
        }
        Ok(self.cots.pop().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread::spawn;

    use scuttlebutt::{channel::unix_channel_pair, Block};

    use rand::{rngs::StdRng, Rng, SeedableRng};

    const GEN_COTS: usize = 1_000_000;

    #[test]
    fn test_ferret() {
        let mut root = StdRng::seed_from_u64(0x5367_FA32_72B1_8478);

        {
            let mut rng1 = StdRng::seed_from_u64(root.gen());
            let mut rng2 = StdRng::seed_from_u64(root.gen());
            let (mut c1, mut c2) = unix_channel_pair();

            let handle = spawn(move || {
                let delta: Block = rng1.gen();
                let mut ys: Vec<Block> = Vec::with_capacity(GEN_COTS);
                let mut sender = Sender::init(delta, &mut c1, &mut rng1).unwrap();
                for _ in 0..GEN_COTS {
                    ys.push(sender.cot(&mut c1, &mut rng1).unwrap());
                }
                (delta, ys)
            });

            let mut xzs: Vec<(bool, Block)> = Vec::with_capacity(GEN_COTS);
            let mut receiver = Receiver::init(&mut c2, &mut rng2).unwrap();
            for _ in 0..GEN_COTS {
                xzs.push(receiver.cot(&mut c2, &mut rng2).unwrap());
            }

            let (delta, ys) = handle.join().unwrap();

            // check correlation
            for (y, (x, mut z)) in ys.into_iter().zip(xzs.into_iter()) {
                if x {
                    z ^= delta;
                }
                assert_eq!(y, z)
            }
        }
    }
}
