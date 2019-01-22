use super::Stream;
use crate::ot::ObliviousTransfer;
use crate::util;
use bitvec::BitVec;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct IKNP<S: Read + Write, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: Read + Write, OT: ObliviousTransfer<S>> ObliviousTransfer<S> for IKNP<S, OT> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let ot = OT::new(stream.clone());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, values: &[(BitVec, BitVec)]) -> Result<(), Error> {
        let m = values.len();
        let s = (0..128).map(|_| self.rng.gen::<bool>()).collect::<BitVec>();
        let mut rs = Vec::with_capacity(128);
        for b in s.iter() {
            let r = self.ot.receive(&[b as u16], m)?;
            rs.push(r[0].clone());
        }
        let mut qs = Vec::with_capacity(m);
        for i in 0..128 {
            let c = rs.iter().map(|r| r.get(i)).collect::<BitVec>();
            qs.push(c)
        }
        for (j, q) in qs.into_iter().enumerate() {
            let y0 = hash(j, &q) ^ util::bitvec_to_u128(&values[j].0);
            let y1 = hash(j, &(q ^ s.clone())) ^ util::bitvec_to_u128(&values[j].1);
            self.stream.write_u128(&y0)?;
            self.stream.write_u128(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[u16], nbits: usize) -> Result<Vec<BitVec>, Error> {
        assert_eq!(nbits, 128); // XXX
        let m = inputs.len();
        let r = inputs.iter().cloned().map(|b| b != 0).collect::<BitVec>();
        let ts = (0..128)
            .map(|_| (0..m).map(|_| self.rng.gen::<bool>()).collect::<BitVec>())
            .collect::<Vec<BitVec>>();
        // let msgs = ts
        //     .into_iter()
        //     .map(|t| (&t, &(t.clone() ^ r.clone())))
        //     .collect::<&[(&BitVec, &BitVec)]>();
        // self.ot.send(msgs);
        for t in ts.iter() {
            self.ot.send(&[(t.clone(), t.clone() ^ r.clone())])?;
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
            out.push(util::u128_to_bitvec(y ^ hash(j, t)))
        }
        Ok(out)
    }
}

fn hash(idx: usize, q: &BitVec) -> u128 {
    let mut h = Sha256::new();
    h.input(idx.to_ne_bytes());
    h.input(q);
    let result = h.result();
    let result = array_ref![result, 0, 16];
    u128::from_ne_bytes(result.clone())
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::ot::chou_orlandi::ChouOrlandiOT;
    use crate::ot::dummy::DummyOT;
    use crate::ot::naor_pinkas::NaorPinkasOT;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
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

    fn test_ot<OT: ObliviousTransfer<UnixStream>>(n: usize) {
        let m0s = rand_u128_vec(n);
        let m1s = rand_u128_vec(n);
        let bs = rand_bool_vec(n);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let bs_ = bs.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            let mut otext = IKNP::<UnixStream, OT>::new(sender.clone());
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .map(|(a, b)| (util::u128_to_bitvec(a), util::u128_to_bitvec(b)))
                .collect::<Vec<(BitVec, BitVec)>>();
            otext.send(&ms).unwrap();
        });
        let mut otext = IKNP::<UnixStream, OT>::new(receiver.clone());
        let results = otext
            .receive(&bs.iter().map(|b| *b as u16).collect::<Vec<u16>>(), 128)
            .unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(util::bitvec_to_u128(&result), if b { m1 } else { m0 })
        }
    }

    #[test]
    fn test_dummy() {
        test_ot::<DummyOT<UnixStream>>(N);
    }
    #[test]
    fn test_naor_pinkas() {
        test_ot::<NaorPinkasOT<UnixStream>>(N);
    }
    #[test]
    fn test_chou_orlandi() {
        test_ot::<ChouOrlandiOT<UnixStream>>(N);
    }

    #[bench]
    fn bench_dummy(b: &mut Bencher) {
        b.iter(|| test_ot::<DummyOT<UnixStream>>(1024))
    }

    #[bench]
    fn bench_naor_pinkas(b: &mut Bencher) {
        b.iter(|| test_ot::<NaorPinkasOT<UnixStream>>(1024))
    }

    #[bench]
    fn bench_chou_orlandi(b: &mut Bencher) {
        b.iter(|| test_ot::<ChouOrlandiOT<UnixStream>>(1024))
    }
}
