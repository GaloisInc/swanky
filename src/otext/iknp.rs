use super::{OTExtension, Stream};
use crate::base::ObliviousTransfer;
use bitvec::BitVec;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::collections::hash_map::DefaultHasher; // XXX
use std::hash::{Hash, Hasher};
use std::io::{Error, Read, Write};

pub struct IKNP<S: Read + Write, OT: ObliviousTransfer> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: Read + Write, OT: ObliviousTransfer> IKNP<S, OT> {
    pub fn new(stream: S, ot: OT) -> Self {
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }
}

impl<S: Read + Write, OT: ObliviousTransfer> OTExtension<OT> for IKNP<S, OT> {
    fn send(&mut self, values: Vec<(u128, u128)>) -> Result<(), Error> {
        let m = values.len();
        let s = (0..128).map(|_| self.rng.gen::<bool>()).collect::<BitVec>();
        let mut rs = Vec::with_capacity(128);
        for b in s.iter() {
            let r = self.ot.receive(b, m)?;
            rs.push(r);
        }
        let mut qs = Vec::with_capacity(m);
        for i in 0..128 {
            let c = rs.iter().map(|r| r.get(i)).collect::<BitVec>();
            qs.push(c)
        }
        for (j, q) in qs.into_iter().enumerate() {
            let y0 = hash(j, &q) ^ values[j].0;
            let y1 = hash(j, &(q ^ s.clone())) ^ values[j].1;
            self.stream.write_u128(&y0)?;
            self.stream.write_u128(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, input: Vec<bool>) -> Result<Vec<u128>, Error> {
        let m = input.len();
        let r = input.into_iter().collect::<BitVec>();
        let ts = (0..128)
            .map(|_| (0..m).map(|_| self.rng.gen::<bool>()).collect::<BitVec>())
            .collect::<Vec<BitVec>>();
        for t in ts.iter() {
            self.ot.send((&t.clone(), &(t.clone() ^ r.clone())))?;
        }
        let mut ts_ = Vec::with_capacity(m);
        for i in 0..128 {
            let c = ts.iter().map(|r| r.get(i)).collect::<BitVec>();
            ts_.push(c)
        }
        let mut out = Vec::with_capacity(m);
        for ((j, b), t) in r.iter().enumerate().zip(ts_.iter()) {
            let y0 = self.stream.read_u128()?;
            let y1 = self.stream.read_u128()?;
            let y = if b { y1 } else { y0 };
            out.push(y ^ hash(j, t))
        }
        Ok(out)
    }
}

fn hash(idx: usize, q: &BitVec) -> u128 {
    let mut h = DefaultHasher::new();
    q.hash(&mut h);
    h.finish().into()
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::base::dummy::DummyOT;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    const N: usize = 256;

    fn rand_u128_vec(size: usize) -> Vec<u128> {
        let mut v = Vec::with_capacity(size);
        for _ in 0..size {
            v.push(rand::random::<u128>());
        }
        v
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        let mut v = Vec::with_capacity(size);
        for _ in 0..size {
            v.push(rand::random::<bool>());
        }
        v
    }

    #[test]
    fn test() {
        let m0s = rand_u128_vec(N);
        let m1s = rand_u128_vec(N);
        let bs = rand_bool_vec(N);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        let (sender_, receiver_) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            let ot = DummyOT::new(sender_);
            let mut otext = IKNP::new(sender, ot);
            otext
                .send(m0s.into_iter().zip(m1s.into_iter()).collect())
                .unwrap();
        });
        let ot = DummyOT::new(receiver_);
        let mut otext = IKNP::new(receiver, ot);
        let results = otext.receive(bs).unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(result, if b { m1 } else { m0 })
        }
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
