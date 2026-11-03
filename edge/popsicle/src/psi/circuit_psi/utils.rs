//! Various utils for PSTY
use crate::cuckoo::CuckooItem;
use fancy_traits::{FancyEncode, FancyReceive};
use itertools::Itertools;
use rand::{CryptoRng, RngExt};
use swanky_block::Block512;
use swanky_channel::Channel;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// Turn a vector of [`F2`] elements into a [`u128`].
///
/// # Panics
/// Panics if the vector contains more than 128 elements.
pub fn binary_to_u128(bin: Vec<F2>) -> u128 {
    assert!(bin.len() <= 128);

    let mut acc: u128 = 0;
    for (i, s) in bin.into_iter().enumerate() {
        acc += (bool::from(s) as u128) << i;
    }
    acc
}

/// Create a vector of [`Block512`]s from a vector of [`u128`]s, where `size`
/// denotes the number of bytes to use from each [`u128`].
///
/// # Panics
/// Panics if `size > 16`.
pub fn int_vec_block512(values: Vec<u128>, size: usize) -> Vec<Block512> {
    assert!(size <= 16);
    values
        .into_iter()
        .map(|item| {
            let bytes = item.to_le_bytes();
            let mut block = [0; 64];
            block[0..size].clone_from_slice(&bytes[..size]);
            Block512::from(block)
        })
        .collect()
}

pub(crate) fn cuckoo_place_ids(
    cuckoo: &[Option<CuckooItem>],
    rng: &mut impl CryptoRng,
) -> Vec<U8x16> {
    cuckoo
        .iter()
        .map(|opt_item| match opt_item {
            Some(item) => item.entry_with_hindex(),
            None => rng.random(),
        })
        .collect::<Vec<U8x16>>()
}

pub(crate) fn cuckoo_place_payloads(
    cuckoo: &[Option<CuckooItem>],
    payloads: &[Block512],
    rng: &mut impl CryptoRng,
) -> Vec<Block512> {
    cuckoo
        .iter()
        .map(|opt_item| match opt_item {
            Some(item) => payloads[item.input_index],
            None => rng.random::<Block512>(),
        })
        .collect::<Vec<Block512>>()
}

/// Encoding ID's before passing them to GC.
/// Note that we are only looking at HASH_SIZE bytes
/// of the IDs.
pub(crate) fn encode_binary(values: &[Block512], input_size: usize) -> Vec<u16> {
    values
        .iter()
        .flat_map(|blk| {
            blk.prefix(input_size)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

/// Flattens bins so that all points in a bin map to the same tag
pub(crate) fn flatten_bin_tags(bins: &[Vec<U8x16>], tags: &[Block512]) -> Vec<(U8x16, Block512)> {
    bins.iter()
        .zip_eq(tags.iter())
        .flat_map(|(bin, &t)| {
            // map all the points in a bin to the same tag
            bin.iter().map(move |&item| (item, t))
        })
        .collect_vec()
}
/// Flattens bins so that all points in a bin map have the correct payloads
pub(crate) fn flatten_bins_payloads(
    bins: &[Vec<U8x16>],
    elements: &[Vec<Block512>],
) -> Vec<(U8x16, Block512)> {
    bins.iter()
        .zip_eq(elements.iter())
        .flat_map(|(bin, t)| {
            bin.iter()
                .zip_eq(t.iter())
                .map(move |(&item, &p)| (item, p))
        })
        .collect_vec()
}

/// A wrapper function that encodes `Block512` as garbled
/// circuit inputs
pub(crate) fn bin_encode_many_block512<F>(
    gc_party: &mut F,
    values: &[Block512],
    size: usize,
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>>
where
    F: FancyEncode<F2>,
{
    let bits = encode_binary(values, size);
    // Then specify the moduli of the wires
    gc_party.encode_many(
        &bits
            .into_iter()
            .map(|bit| F2::from(bit != 0))
            .collect::<Vec<_>>(),
        channel,
    )
}

/// A wrapper function that encodes `Block512` as garbled
/// circuit inputs
pub(crate) fn bin_receive_many_block512<F>(
    gc_party: &mut F,
    size: usize,
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>>
where
    F: FancyReceive<F2>,
{
    // Specify the moduli of the wires
    gc_party.receive_many(size, channel)
}
