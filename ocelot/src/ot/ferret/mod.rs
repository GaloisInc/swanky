// mod ferret;
pub(crate) mod cache;
pub(crate) mod ferret;
pub(crate) mod lpn;
pub(crate) mod mpcot;
pub(crate) mod spcot;
pub(crate) mod util;

mod receiver;
mod sender;

use receiver::Receiver;
use sender::Sender;

use scuttlebutt::AesHash;

// The computational security parameter: \kappa in the paper.
const CSP: usize = 128;

// ferret with regular error (default, fastest)
pub type FerretSender = Sender<true>;
pub type FerretReceiver = Receiver<true>;

// ferret with uniform error (more conservative LPN assumption)
pub type FerretSenderUniform = Sender<false>;
pub type FerretReceiverUniform = Receiver<false>;

// used to break the COT correlation for when ROT is desired
fn cr_cot_hash() -> AesHash {
    AesHash::new([1u8; 16].into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread::spawn;

    use scuttlebutt::{channel::unix_channel_pair, Block};

    use rand::{rngs::StdRng, Rng, SeedableRng};

    const GEN_COTS: usize = 1_000_000;

    #[test]
    fn test_ferret_reg() {
        test_ferret::<true>();
    }

    #[test]
    fn test_ferret_uni() {
        test_ferret::<false>();
    }

    fn test_ferret<const REG: bool>() {
        let mut root = StdRng::seed_from_u64(0x5367_FA32_72B1_8478);

        {
            let mut rng1 = StdRng::seed_from_u64(root.gen());
            let mut rng2 = StdRng::seed_from_u64(root.gen());
            let (mut c1, mut c2) = unix_channel_pair();

            let handle = spawn(move || {
                let delta: Block = rng1.gen();
                let mut ys: Vec<Block> = Vec::with_capacity(GEN_COTS);
                let mut sender = Sender::<REG>::init(delta, &mut c1, &mut rng1).unwrap();
                for _ in 0..GEN_COTS {
                    ys.push(sender.cot(&mut c1, &mut rng1).unwrap());
                }
                (delta, ys)
            });

            let mut xzs: Vec<(bool, Block)> = Vec::with_capacity(GEN_COTS);
            let mut receiver = Receiver::<REG>::init(&mut c2, &mut rng2).unwrap();
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
