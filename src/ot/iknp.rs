use super::Stream;
use crate::ot::ObliviousTransfer;
use failure::Error;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct IknpOT<S: Read + Write + Send, OT: ObliviousTransfer<S>> {
    stream: Stream<S>,
    ot: OT,
    rng: ThreadRng,
}

impl<S: Read + Write + Send, OT: ObliviousTransfer<S>> ObliviousTransfer<S> for IknpOT<S, OT> {
    fn new(stream: Arc<Mutex<S>>) -> Self {
        let ot = OT::new(stream.clone());
        let stream = Stream::new(stream);
        let rng = rand::thread_rng();
        Self { stream, ot, rng }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], nbytes: usize) -> Result<(), Error> {
        let m = inputs.len();
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        if m <= 128 {
            // Just do normal OT
            return self.ot.send(inputs, nbytes);
        }
        let (nrows, ncols) = (128, m);
        let cipher = super::cipher(&[0u8; 16]);
        let s = (0..128)
            .map(|_| self.rng.gen::<bool>())
            .collect::<Vec<bool>>();
        let qs = self.ot.receive(&s, ncols / 8)?;
        let qs = qs.into_iter().flatten().collect::<Vec<u8>>();
        let qs = super::transpose(&qs, nrows, ncols);
        let s = super::boolvec_to_u8vec(&s);
        for j in 0..ncols {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let q = qs.get(range).unwrap();
            let y0 = super::xor(&super::hash(j, &q, &cipher), &inputs[j].0);
            let y1 = super::xor(&super::hash(j, &super::xor(&q, &s), &cipher), &inputs[j].1);
            self.stream.write_bytes(&y0)?;
            self.stream.write_bytes(&y1)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        if nbytes != 16 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "IKNP OT only supports 128-bit inputs",
            )));
        }
        let m = inputs.len();
        if m <= 128 {
            // Just do normal OT
            return self.ot.receive(inputs, nbytes);
        }
        let (nrows, ncols) = (128, m);
        let cipher = super::cipher(&[0u8; 16]);
        let r = super::boolvec_to_u8vec(inputs);
        let ts = (0..128)
            .map(|_| {
                let bv = (0..m)
                    .map(|_| self.rng.gen::<bool>())
                    .collect::<Vec<bool>>();
                super::boolvec_to_u8vec(&bv)
            })
            .map(|t| (t.clone(), super::xor(&t, &r)))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        self.ot.send(&ts, m / 8)?;
        let ts = ts.into_iter().flat_map(|(t, _)| t).collect::<Vec<u8>>();
        let ts = super::transpose(&ts, nrows, ncols);
        let mut out = Vec::with_capacity(m);
        for (j, b) in inputs.iter().enumerate() {
            let range = j * nrows / 8..(j + 1) * nrows / 8;
            let t = ts.get(range).unwrap();
            let y0 = self.stream.read_bytes(16)?;
            let y1 = self.stream.read_bytes(16)?;
            let y = if *b { y1 } else { y0 };
            let r = super::xor(&y, &super::hash(j, &t, &cipher));
            out.push(r);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use crate::*;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    const N: usize = 1 << 12;

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
                .map(|(a, b)| (a.to_le_bytes().to_vec(), b.to_le_bytes().to_vec()))
                .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
            otext.send(&ms, 16).unwrap();
        });
        let mut otext = IknpOT::<UnixStream, OT>::new(receiver.clone());
        let results = otext.receive(&bs, 16).unwrap();
        for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
            assert_eq!(
                u128::from_ne_bytes(*array_ref![result, 0, 16]),
                if b { m1 } else { m0 }
            )
        }
    }

    #[test]
    fn test() {
        test_ot::<DummyOT<UnixStream>>(N);
    }
}
