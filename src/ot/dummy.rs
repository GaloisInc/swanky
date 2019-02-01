use crate::stream::Stream;
use crate::ObliviousTransfer;
use failure::Error;
use std::io::{Read, Write};

/// Implementation if an **entirely insecure** oblivious transfer protocol for
/// testing purposes.
pub struct DummyOT<T: Read + Write + Send> {
    stream: Stream<T>,
}

impl<T: Read + Write + Send> ObliviousTransfer<T> for DummyOT<T> {
    fn new(stream: T) -> Self {
        let stream = Stream::new(stream);
        Self { stream }
    }

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)], _nbytes: usize) -> Result<(), Error> {
        let mut bs = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let b = self.stream.read_bool()?;
            bs.push(b);
        }
        for (b, m) in bs.into_iter().zip(inputs.iter()) {
            let m = if b { &m.1 } else { &m.0 };
            self.stream.write_bytes(&m)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        for b in inputs.iter() {
            self.stream.write_bool(*b)?;
        }
        (0..inputs.len())
            .map(|_| self.stream.read_bytes(nbytes))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;

    const N: usize = 16;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>().to_vec();
        let m1 = rand::random::<[u8; N]>().to_vec();
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2), // (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2)))
            Err(e) => panic!("Couldn't create pair of sockets: {:?}", e),
        };
        let handle = std::thread::spawn(|| {
            let mut ot = DummyOT::new(sender);
            ot.send(&[(m0, m1)], N).unwrap();
        });
        let mut ot = DummyOT::new(receiver);
        let result = ot.receive(&[b], N).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        handle.join().unwrap();
    }
}
