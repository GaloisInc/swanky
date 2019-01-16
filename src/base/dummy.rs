use super::{ObliviousTransfer, Stream};
use std::io::{Error, Read, Write};

pub struct DummyOT<T: Read + Write> {
    stream: Stream<T>,
}

impl<T: Read + Write> DummyOT<T> {
    pub fn new(stream: T) -> Self {
        let stream = Stream::new(stream);
        Self { stream }
    }
}

impl<T: Read + Write> ObliviousTransfer for DummyOT<T> {
    fn send(&mut self, values: (&[u8], &[u8])) -> Result<(), Error> {
        let input = self.stream.read_bool()?;
        self.stream
            .write_bytes(if input { values.1 } else { values.0 })?;
        Ok(())
    }

    fn receive(&mut self, input: bool, length: usize) -> Result<Vec<u8>, Error> {
        self.stream.write_bool(input)?;
        let output = self.stream.read_bytes(length)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; 8]>();
        let m1 = rand::random::<[u8; 8]>();
        let b = rand::random::<bool>();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return;
            }
        };
        std::thread::spawn(move || {
            let mut ot = DummyOT::new(sender);
            ot.send((&m0, &m1)).unwrap();
        });
        let mut ot = DummyOT::new(receiver);
        let result = ot.receive(b, 8).unwrap();
        assert_eq!(result, if b { m1 } else { m0 });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
