use super::{ObliviousTransfer, Stream};
use bitvec::BitVec;
use std::io::{Error, Read, Write};

pub struct DummyOT<T: Read + Write> {
    stream: Stream<T>,
}

impl<T: Read + Write> ObliviousTransfer<T> for DummyOT<T> {
    fn new(stream: T) -> Self {
        let stream = Stream::new(stream);
        Self { stream }
    }

    fn send(&mut self, values: (&BitVec, &BitVec)) -> Result<(), Error> {
        let input = self.stream.read_bool()?;
        let value = if input { &values.1 } else { &values.0 };
        self.stream.write_bitvec(&value)?;
        Ok(())
    }

    fn receive(&mut self, input: bool, nbits: usize) -> Result<BitVec, Error> {
        self.stream.write_bool(&input)?;
        let output = self.stream.read_bitvec(nbits)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use std::os::unix::net::UnixStream;
    use test::Bencher;

    const N: usize = 8;

    #[test]
    fn test() {
        let m0 = rand::random::<[u8; N]>();
        let m1 = rand::random::<[u8; N]>();
        let m0 = BitVec::from(m0.to_vec());
        let m1 = BitVec::from(m1.to_vec());
        let b = rand::random::<bool>();
        let m0_ = m0.clone();
        let m1_ = m1.clone();
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
        let result = ot.receive(b, N * 8).unwrap();
        assert_eq!(result, if b { m1_ } else { m0_ });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
