use super::Stream;
use crate::ot::ObliviousTransfer;
use crate::util;
use bitvec::BitVec;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct IknpOT<S: Read + Write, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: Read + Write, OT: ObliviousTransfer<S>> ObliviousTransfer<S> for IknpOT<S, OT> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let ot = OT::new(stream.clone());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, inputs: &[(BitVec, BitVec)]) -> Result<(), Error> {
        let m = inputs.len();
        if m <= 128 {
            // Just do normal OT
            return self.ot.send(inputs);
        }
        let s = (0..128)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let rs = self.ot.receive(&s, m)?;
        let qs = (0..128).map(|i| rs.iter().map(|r| r.get(i).unwrap()).collect::<BitVec>());
        for (j, q) in qs.into_iter().enumerate() {
            let y0 = hash(j, &q) ^ util::bitvec_to_u128(inputs[j].0.clone());
            let y1 = hash(j, &(q ^ s.clone())) ^ util::bitvec_to_u128(inputs[j].1.clone());
            self.stream.write_u128(&y0)?;
            self.stream.write_u128(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbits: usize) -> Result<Vec<BitVec>, Error> {
        if nbits != 128 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Currently only supports 128-bit inputs",
            )));
        }
        let m = inputs.len();
        if m <= 128 {
            // Just do normal OT
            return self.ot.receive(inputs, nbits);
        }
        let r = inputs.iter().cloned().collect::<BitVec>();
        let ts = (0..128)
            .map(|_| (0..m).map(|_| self.rng.gen::<bool>()).collect::<BitVec>())
            .map(|t| (t.clone(), t.clone() ^ r.clone()))
            .collect::<Vec<(BitVec, BitVec)>>();
        self.ot.send(&ts)?;
        let mut ts_ = Vec::with_capacity(m);
        for i in 0..128 {
            let c = ts.iter().map(|r| r.0.get(i).unwrap()).collect::<BitVec>();
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

    const N: usize = 256;

    fn rand_u128_vec(size: usize) -> Vec<u128> {
        (0..size).map(|_| rand::random::<u128>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
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
            let mut otext = IknpOT::<UnixStream, OT>::new(sender.clone());
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .map(|(a, b)| (util::u128_to_bitvec(a), util::u128_to_bitvec(b)))
                .collect::<Vec<(BitVec, BitVec)>>();
            otext.send(&ms).unwrap();
        });
        let mut otext = IknpOT::<UnixStream, OT>::new(receiver.clone());
        let results = otext.receive(&bs, 128).unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(util::bitvec_to_u128(result), if b { m1 } else { m0 })
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
}
