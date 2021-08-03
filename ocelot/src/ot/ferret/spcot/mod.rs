//! Implementation of the SPCOT protocol of Ferret (Figure 6.)
//!
//! The notation is kept as close as possible to that of the paper.

mod receiver;
mod sender;

use super::CSP;

pub(crate) use receiver::Receiver;
pub(crate) use sender::Sender;

use scuttlebutt::{Aes128, AesHash, Block};

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

mod tests {
    use super::*;

    use std::thread::spawn;

    use rand::{rngs::OsRng, Rng};
    use scuttlebutt::channel::unix_channel_pair;

    use simple_logger;

    use crate::ot::{KosDeltaReceiver, KosDeltaSender};

    #[test]
    fn test() {
        let _ = simple_logger::init();
        let (mut c1, mut c2) = unix_channel_pair();

        let num = 2;

        let handle = spawn(move || {
            let mut send: Sender<KosDeltaSender> = Sender::init(&mut c2, &mut OsRng).unwrap();
            let v = send.extend::<_, _, 2, 4>(&mut c2, &mut OsRng, num).unwrap();
            println!("{:?}", v);
            (send.delta(), v)
        });

        let mut recv: Receiver<KosDeltaReceiver> = Receiver::init(&mut c1, &mut OsRng).unwrap();
        //( let out = recv.receive_random(&mut c1, &[true], &mut OsRng).unwrap();

        let mut alpha: Vec<usize> = (0..num).map(|_| OsRng.gen::<usize>() % 4).collect();

        let w = recv
            .extend::<_, _, 2, 4>(&alpha[..], &mut c1, &mut OsRng)
            .unwrap();
        println!("{:?}", w);

        let (delta, mut v) = handle.join().unwrap();

        for i in 0..num {
            v[i][alpha[i]] ^= delta;
        }

        assert_eq!(v, w, "correlation not satisfied");
    }
}
