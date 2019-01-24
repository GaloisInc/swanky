use super::{ObliviousTransfer, Stream};
use bitvec::BitVec;
use failure::Error;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct DummyOT<T: Read + Write> {
    stream: Stream<T>,
}

impl<T: Read + Write> ObliviousTransfer<T> for DummyOT<T> {
    fn new(stream: Arc<Mutex<T>>) -> Self {
        let stream = Stream::new(stream);
        Self { stream }
    }

    fn send(&mut self, inputs: &[(BitVec, BitVec)]) -> Result<(), Error> {
        for input in inputs.into_iter() {
            let b = self.stream.read_bool()?;
            let m = if b { &input.1 } else { &input.0 };
            self.stream.write_bitvec(&m)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbits: usize) -> Result<Vec<BitVec>, Error> {
        let mut outputs = Vec::with_capacity(inputs.len());
        for b in inputs.iter() {
            self.stream.write_bool(*b)?;
            let output = self.stream.read_bitvec(nbits)?;
            outputs.push(output);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    const N: usize = 8;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>().to_vec();
        let m1 = rand::random::<[u8; N]>().to_vec();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        let handle = std::thread::spawn(|| {
            let mut ot = DummyOT::new(sender);
            ot.send(&[(BitVec::from(m0), BitVec::from(m1))]).unwrap();
        });
        let mut ot = DummyOT::new(receiver);
        let result = ot.receive(&[b], N * 8).unwrap();
        assert_eq!(
            result[0],
            BitVec::<bitvec::BigEndian>::from(if b { m1_ } else { m0_ })
        );
        handle.join();
    }
}
