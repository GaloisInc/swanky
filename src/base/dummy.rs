use super::ObliviousTransfer;
use std::io::{Error, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

pub struct DummyOT<T: Read + Write> {
    stream: Arc<Mutex<T>>,
}

impl<T: Read + Write> DummyOT<T> {
    pub fn new(stream: Arc<Mutex<T>>) -> Self {
        Self { stream }
    }
}

impl<T: Read + Write> ObliviousTransfer for DummyOT<T>
{
    fn send(&mut self, values: Vec<u128>) -> Result<(), Error> {
        let mut input = [0; 8];
        self.stream.lock().unwrap().read_exact(&mut input)?;
        let input = usize::from_ne_bytes(input);
        if input >= values.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid input length"));
        }
        self.stream.lock().unwrap().write(&u128::to_ne_bytes(values[input]))?;
        Ok(())
    }

    fn receive(&mut self, input: usize) -> Result<u128, Error> {
        let mut output = [0; 16];
        self.stream.lock().unwrap().write(&usize::to_ne_bytes(input))?;
        self.stream.lock().unwrap().read_exact(&mut output)?;
        Ok(u128::from_ne_bytes(output))
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
        let m0 = rand::random::<u128>();
        let m1 = rand::random::<u128>();
        let b = rand::random::<bool>();
        let (sender, receiver) = match UnixStream::pair() {
            Ok((s1, s2)) => (s1, s2),
            Err(e) => {
                eprintln!("Couldn't create pair of sockets: {:?}", e);
                return
            }
        };
        std::thread::spawn(move || {
            let mut ot = DummyOT::new(Arc::new(Mutex::new(sender)));
            ot.send(vec![m0, m1]).unwrap();
        });
        let mut ot = DummyOT::new(Arc::new(Mutex::new(receiver)));
        let result = ot.receive(b as usize).unwrap();
        assert_eq!(result, if b { m1 } else { m0 });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        b.iter(|| test())
    }
}
