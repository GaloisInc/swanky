//! Various utility functionalities for tests

#[cfg(test)]
use scuttlebutt::Channel;

#[cfg(test)]
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

#[cfg(test)]
/// Turns a Unixstream into a scuttlebutt channel
pub fn setup(stream: UnixStream) -> Channel<BufReader<UnixStream>, BufWriter<UnixStream>> {
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let channel = Channel::new(reader, writer);
    channel
}
