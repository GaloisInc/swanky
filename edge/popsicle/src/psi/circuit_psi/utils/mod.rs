//! Various utils for PSTY
use crate::cuckoo::CuckooItem;
use fancy_circuits::util::{PRIMES, crt, crt_inv, primes_with_width};
use fancy_traits::FancyEncode;
use itertools::Itertools;
use rand::{CryptoRng, RngExt, SeedableRng};
use swanky_block::{Block, Block512};
use swanky_channel::Channel;

/// Turn a vector of bits represented as u16 into a decimal
/// value represented as a u128.
/// We represent bits as u16 in accordance with fancy's representation
pub fn binary_to_u128(bin: Vec<u16>) -> u128 {
    let mut acc: u128 = 0;
    for (i, s) in bin.into_iter().enumerate() {
        acc += (s as u128) << i;
    }
    acc
}

fn block512_to_crt(b: Block512, size: usize) -> Vec<u16> {
    let size_b = size / 8;
    let b_val = b.prefix(size_b);

    let mut b_128 = [0_u8; 16];
    b_128[..size_b].clone_from_slice(&b_val[..size_b]);

    let q = primes_with_width(size);
    crt(u128::from_le_bytes(b_128), &q)
}

/// Hide a value with a mask under crt. Assumes payloads are up to 64bit long
pub fn mask_payload_crt(x: Block512, y: Block512, size: usize) -> Block512 {
    let x_crt = block512_to_crt(x, size);
    let y_crt = block512_to_crt(y, size);

    let q = primes_with_width(size);

    let mut res_crt = Vec::new();
    for i in 0..q.len() {
        res_crt.push((x_crt[i] + y_crt[i]) % q[i]);
    }
    let res = crt_inv(&res_crt, &q).to_le_bytes();
    let y_bytes = y.prefix(size);
    let mut block = [0_u8; 64];
    for i in 0..size {
        if i < size / 8 {
            block[i] = res[i];
        } else {
            block[i] = y_bytes[i];
        }
    }
    Block512::from(block)
}

/// Hide a value with a mask under crt. Assumes payloads are up to 64bit long
pub fn mask_payload_binary(x: Block512, y: Block512) -> Block512 {
    x ^ y
}

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

pub(crate) fn cuckoo_place_ids<RNG: CryptoRng + SeedableRng>(
    cuckoo: &[Option<CuckooItem>],
    rng: &mut RNG,
) -> Vec<Block> {
    cuckoo
        .iter()
        .map(|opt_item| match opt_item {
            Some(item) => item.entry_with_hindex(),
            None => rng.random(),
        })
        .collect::<Vec<Block>>()
}

pub(crate) fn cuckoo_place_payloads<RNG: CryptoRng + SeedableRng>(
    cuckoo: &[Option<CuckooItem>],
    payloads: &[Block512],
    rng: &mut RNG,
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
pub fn encode_binary(values: &[Block512], input_size: usize) -> Vec<u16> {
    values
        .iter()
        .flat_map(|blk| {
            blk.prefix(input_size)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

/// Encoding Payloads's before passing them to GC.
/// Note that we are only looking at PAYLOAD_SIZE bytes
/// of the payloads.
pub fn encode_crt(values: &[Block512], output_size: usize, input_size: usize) -> Vec<u16> {
    let q = &PRIMES[..output_size];
    values
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(input_size);
            let mut b_8 = [0_u8; 16];
            b_8[..input_size].copy_from_slice(&b[..input_size]);
            crt(u128::from_le_bytes(b_8), q)
        })
        .collect()
}

/// Split a table into megabins of size "megasize". This is useful when parallelizing PSTY
pub fn split_into_megabins<T: Clone>(table: &[T], megasize: usize) -> Vec<Vec<T>> {
    table.chunks(megasize).map(|x| x.to_vec()).collect()
}

/// Flattens bins so that all points in a bin map to the same tag
pub fn flatten_bin_tags(bins: &[Vec<Block>], tags: &[Block512]) -> Vec<(Block, Block512)> {
    bins.iter()
        .zip_eq(tags.iter())
        .flat_map(|(bin, &t)| {
            // map all the points in a bin to the same tag
            bin.iter().map(move |&item| (item, t))
        })
        .collect_vec()
}
/// Flattens bins so that all points in a bin map have the correct payloads
pub fn flatten_bins_payloads(
    bins: &[Vec<Block>],
    elements: &[Vec<Block512>],
) -> Vec<(Block, Block512)> {
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
pub fn bin_encode_many_block512<F>(
    gc_party: &mut F,
    values: &[Block512],
    size: usize,
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>>
where
    F: FancyEncode,
{
    let bits = encode_binary(values, size);
    // Then specify the moduli of the wires
    let moduli = vec![2; bits.len()];
    gc_party.encode_many(&bits, &moduli, channel)
}

/// A wrapper function that encodes `Block512` as garbled
/// circuit inputs
pub fn bin_receive_many_block512<F>(
    gc_party: &mut F,
    size: usize,
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>>
where
    F: FancyEncode,
{
    // Specify the moduli of the wires
    let moduli = vec![2; size];
    gc_party.receive_many(&moduli, channel)
}
