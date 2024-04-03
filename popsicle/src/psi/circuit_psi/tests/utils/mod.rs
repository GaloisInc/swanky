//! Various utility functionalities for tests

#[cfg(test)]
use scuttlebutt::{Block, Block512, Channel};

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

#[cfg(test)]
/// Create a vector of Block512, from a vector of u64s
pub fn int_vec_block512(values: Vec<u128>, size: usize) -> Vec<Block512> {
    values
        .into_iter()
        .map(|item| {
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0_u8; 64];
            res_block[0..size].clone_from_slice(&value_bytes[..size]);
            Block512::from(res_block)
        })
        .collect()
}

#[cfg(test)]
/// Create a vector of Block512, from a vector of u64s
pub fn u8_vec_block(values: &[Vec<u8>], size: usize) -> Vec<Block> {
    values
        .into_iter()
        .map(|item| {
            let mut res_block = [0_u8; 16];
            res_block[0..size].clone_from_slice(&item[..size]);
            Block::from(res_block)
        })
        .collect()
}
