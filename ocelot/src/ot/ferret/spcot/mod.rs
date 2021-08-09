//! Implementation of the SPCOT protocol of Ferret (Figure 6.)
//!
//! The notation is kept as close as possible to that of the paper.

mod receiver;
mod sender;

use super::CSP;

pub(crate) use receiver::Receiver;
pub(crate) use sender::Sender;

use sha2::{Digest, Sha256};

use scuttlebutt::{Aes128, AesHash, Block, F128};

fn ro_hash(b: Block) -> [u8; 32] {
    let mut hsh = Sha256::default();
    hsh.update(b.as_ref());
    hsh.finalize().into()
}

fn cr_hash() -> AesHash {
    AesHash::new(Default::default())
}

#[inline(always)]
fn bitn(size: usize, idx: usize, n: usize) -> bool {
    (n >> (size - idx)) & 1 != 0
}

fn prg2(k: Block) -> (Block, Block) {
    let aes = Aes128::new(k);
    (
        aes.encrypt(Block::from(0u128)),
        aes.encrypt(Block::from(1u128)),
    )
}

// MSB
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

fn pack_bits(bits: &[bool]) -> usize {
    debug_assert!(bits.len() <= 64);
    let mut n = 0;
    for b in bits.iter().copied() {
        n <<= 1;
        n |= b as usize;
    }
    n
}

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

mod tests {
    use super::*;

    use std::thread::spawn;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use scuttlebutt::channel::unix_channel_pair;

    use simple_logger;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender};

    use std::convert::TryFrom;

    #[test]
    fn test_decompose() {
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
    fn test() {
        // de-randomize the test
        let mut rng1 = StdRng::seed_from_u64(0x5322_FA41_6AB1_521A);
        let mut rng2 = StdRng::seed_from_u64(0x8DEE_F32A_8712_321F);

        let _ = simple_logger::init();
        let (mut c1, mut c2) = unix_channel_pair();

        let num = 1;

        let handle = spawn(move || {
            let mut send: Sender<KosDeltaSender> = Sender::init(&mut c2, &mut rng1).unwrap();
            let v = send.extend::<_, _, 2, 4>(&mut c2, &mut rng1, num).unwrap();
            println!("{:?}", v);
            (send.delta(), v)
        });

        let mut recv: Receiver<KosDeltaReceiver> = Receiver::init(&mut c1, &mut rng2).unwrap();
        //( let out = recv.receive_random(&mut c1, &[true], &mut OsRng).unwrap();

        let alpha: Vec<usize> = (0..num).map(|_| rng2.gen::<usize>() % 4).collect();

        let w = recv
            .extend::<_, _, 2, 4>(&alpha[..], &mut c1, &mut rng2)
            .unwrap();
        println!("{:?}", w);

        let (delta, mut v) = handle.join().unwrap();

        for i in 0..num {
            v[i][alpha[i]] ^= delta;
        }

        assert_eq!(v, w, "correlation not satisfied");
    }
}
