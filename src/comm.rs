use failure::Error;
use std::io::{Read, Write};

pub fn send<T: Read + Write>(stream: &mut T, data: &[u8]) -> Result<(), Error> {
    let len = data.len().to_ne_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

pub fn receive<T: Read + Write>(stream: &mut T) -> Result<Vec<u8>, Error> {
    let mut bytes: [u8; 8] = Default::default();
    stream.read_exact(&mut bytes)?;
    let len = usize::from_ne_bytes(bytes);
    let mut v = Vec::with_capacity(len);
    v.resize(len, 0);
    stream.read_exact(&mut v)?;
    Ok(v)
}
