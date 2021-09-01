//! Implementation of the SPCOT protocol of Ferret (Figure 6.)
//!
//! The notation is kept as close as possible to that of the paper.

mod generator;
mod receiver;
mod sender;

use super::{
    cache::{CachedReceiver, CachedSender},
    CSP,
};

pub(crate) use generator::BiasedGen;
pub(crate) use receiver::Receiver;
pub(crate) use sender::Sender;

use sha2::{Digest, Sha256};

use scuttlebutt::{AesHash, Block, F128};

fn ro_hash(b: Block) -> [u8; 32] {
    let mut hsh = Sha256::default();
    hsh.update(b.as_ref());
    hsh.finalize().into()
}

fn cr_hash() -> AesHash {
    AesHash::new(Default::default())
}

// Length doubling PRG
// Avoid running the AES key-schedule for each k
#[inline(always)]
fn prg2(h: &AesHash, k1: Block) -> (Block, Block) {
    let o1 = h.cr_hash(Block::default(), k1);
    let o2: Block = (u128::from(o1).wrapping_add(u128::from(k1))).into();
    // let o2 = h.cr_hash(Block::default(), k2);
    (o1, o2)
}

#[inline]
fn unpack_bits<const N: usize>(mut n: usize) -> [bool; N] {
    debug_assert!(n < (1 << N));
    let mut b: [bool; N] = [false; N];
    let mut j: usize = N - 1;
    loop {
        b[j] = (n & 1) != 0;
        n >>= 1;
        if j == 0 {
            break b;
        }
        j -= 1;
    }
}

#[inline]
fn pack_bits(bits: &[bool]) -> usize {
    debug_assert!(bits.len() <= 64);
    let mut n = 0;
    for b in bits.iter().copied() {
        n <<= 1;
        n |= b as usize;
    }
    n
}

#[inline]
fn stack_cyclic<T: Copy>(elems: &[T; 128]) -> F128
where
    T: Into<F128>,
{
    let mut res: F128 = F128::zero();
    for z in elems.iter().copied() {
        res = res.mul_x();
        res = res + z.into();
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread::spawn;

    use crate::ot::FixedKeyInitializer;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use scuttlebutt::channel::unix_channel_pair;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender, Receiver as OtReceiver};

    use std::convert::TryFrom;

    #[test]
    fn test_decompose_cyclic() {
        debug_assert_eq!(F128::zero(), F128::zero().mul_x());
        let mut rng = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        for _ in 0..10 {
            let a: Block = rng.gen();
            let a_bits: [bool; 128] = a.into();
            let a_elem: Vec<F128> = a_bits
                .iter()
                .copied()
                .map(|bit| if bit { F128::one() } else { F128::zero() })
                .collect();
            let a_new = stack_cyclic(<&[F128; 128]>::try_from(&a_elem[..]).unwrap());
            assert_eq!(a_new, a.into());
        }
    }

    #[test]
    fn test_cyclic_mul_rnd() {
        let mut rng = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        for _ in 0..10 {
            let a: Block = rng.gen();
            let b: Block = rng.gen();
            let a_bits: [bool; 128] = a.into();
            let ab_elems: Vec<F128> = a_bits
                .iter()
                .copied()
                .map(|bit| if bit { b.into() } else { F128::zero() })
                .collect();
            let a: F128 = a.into();
            let b: F128 = b.into();
            assert_eq!(
                stack_cyclic(<&[F128; 128]>::try_from(&ab_elems[..]).unwrap()),
                a * b
            )
        }
    }

    fn test_spcot_correlation<const H: usize, const N: usize>(num: usize) {
        let mut root = StdRng::seed_from_u64(0x5367_FA32_72B1_8478);
        for _ in 0..10 {
            // de-randomize the test
            let mut rng1 = StdRng::seed_from_u64(root.gen());
            let mut rng2 = StdRng::seed_from_u64(root.gen());

            let (mut c1, mut c2) = unix_channel_pair();

            let handle = spawn(move || {
                let delta: Block = rng1.gen();
                let mut cache: CachedSender = CachedSender::new(delta);
                let mut kos18 =
                    KosDeltaSender::init_fixed_key(&mut c2, delta.into(), &mut rng1).unwrap();
                cache
                    .generate(&mut kos18, &mut c2, &mut rng1, H * num + CSP)
                    .unwrap();
                let mut send: Sender = Sender::init(delta);
                let v = send
                    .extend::<_, _, H, N>(&mut cache, &mut c2, &mut rng1, num)
                    .unwrap();
                (delta, v)
            });

            let mut cache: CachedReceiver = CachedReceiver::default();

            let mut kos18 = KosDeltaReceiver::init(&mut c1, &mut rng2).unwrap();

            cache
                .generate(&mut kos18, &mut c1, &mut rng2, H * num + CSP)
                .unwrap();

            let mut recv: Receiver = Receiver::init();
            //( let out = recv.receive_random(&mut c1, &[true], &mut OsRng).unwrap();

            let alpha: Vec<usize> = (0..num).map(|_| rng2.gen::<usize>() % N).collect();

            let w = recv
                .extend::<_, _, H, N>(&mut cache, &mut c1, &mut rng2, &alpha[..])
                .unwrap();

            let (delta, mut v) = handle.join().unwrap();

            for i in 0..num {
                v[i][alpha[i]] ^= delta;
            }

            assert_eq!(v, w, "correlation not satisfied");
        }
    }

    #[test]
    fn test_spcot_correlation_h2() {
        for i in vec![1, 2, 5, 10].into_iter() {
            test_spcot_correlation::<2, 4>(i);
        }
    }

    #[test]
    fn test_spcot_correlation_h3() {
        for i in vec![1, 2, 5, 10].into_iter() {
            test_spcot_correlation::<3, 8>(i);
        }
    }

    #[test]
    fn test_spcot_correlation_h4() {
        for i in vec![1, 2, 5, 10].into_iter() {
            test_spcot_correlation::<4, 16>(i);
        }
    }

    #[test]
    fn test_spcot_correlation_h5() {
        for i in vec![1, 2, 5, 10].into_iter() {
            test_spcot_correlation::<5, 32>(i);
        }
    }

    #[test]
    fn test_spcot_correlation_h6() {
        for i in vec![1, 2, 5, 10].into_iter() {
            test_spcot_correlation::<5, 32>(i);
        }
    }
}
