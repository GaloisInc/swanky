//! Various utility functionalities for tests

#[cfg(test)]
use scuttlebutt::{Block, Block512, Channel};

#[cfg(test)]
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

#[cfg(test)]
use proptest::{collection, strategy::Strategy};

#[cfg(test)]
/// Turns a Unixstream into a scuttlebutt channel
pub fn setup(stream: UnixStream) -> Channel<BufReader<UnixStream>, BufWriter<UnixStream>> {
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let channel = Channel::new(reader, writer);
    channel
}

#[cfg(test)]
/// Create a proptest strategy that creates sets of elements represented as vectors of bytes.
/// Reminder: sets have unique elements, we ensure this by generating hashsets using proptests
/// and turning them into vecs.
pub fn arbitrary_unique_sets(size: usize, max_value: u128) -> impl Strategy<Value = Vec<Vec<u8>>> {
    collection::hash_set(0..max_value, size).prop_map(|v| {
        v.into_iter()
            .map(|value| value.to_le_bytes().to_vec())
            .collect()
    })
}

#[cfg(test)]
/// Create a proptest strategy that creates payloads represented as u128.
pub fn arbitrary_payloads_u128(size: usize, max_value: u128) -> impl Strategy<Value = Vec<u128>> {
    collection::vec(0..max_value, size)
}

#[cfg(test)]
/// Create a proptest strategy that creates payloads represented as Block512.
pub fn arbitrary_payloads_block125(
    size: usize,
    max_value: u128,
) -> impl Strategy<Value = Vec<Block512>> {
    collection::vec(0..max_value, size).prop_map(|v| {
        v.into_iter()
            .map(|value| {
                let value_bytes = value.to_le_bytes();
                let mut value_block512 = [0u8; 64];
                value_block512[0..16].clone_from_slice(&value_bytes[..16]);
                Block512::from(value_block512)
            })
            .collect()
    })
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
