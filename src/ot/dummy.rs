use super::{ObliviousTransfer, Stream};
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

    fn send(&mut self, inputs: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
        for input in inputs.into_iter() {
            let b = self.stream.read_bool()?;
            let m = if b { &input.1 } else { &input.0 };
            self.stream.write_bytes(&m)?;
        }
        Ok(())
    }

    fn receive(&mut self, inputs: &[bool], nbytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        let mut outputs = Vec::with_capacity(inputs.len());
        for b in inputs.iter() {
            self.stream.write_bool(*b)?;
            let output = self.stream.read_bytes(nbytes)?;
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
            ot.send(&[(m0, m1)]).unwrap();
        });
        let mut ot = DummyOT::new(receiver);
        let result = ot.receive(&[b], N).unwrap();
        assert_eq!(result[0], if b { m1_ } else { m0_ });
        let _ = handle.join();
    }
}
