//! Various fancy circuits
use itertools::Itertools;

use fancy_garbling::{BinaryBundle, BinaryGadgets, Fancy, FancyBinary, FancyReveal};

// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 8;

/// Fancy function to compute the intersection of two sets
/// and return a bit vector indicating the presence or abscence of
/// elements.
/// The sender and receiver slices are assumed to be of the same size
/// and ordered in such a way that if elements are shared between them
/// then they will be in the same position.
pub fn fancy_intersection_bit_vector<F>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<Vec<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + FancyBinary,
{
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.bin_eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect()
}

/// Fancy function that turns a slice of binary wires into a vector of BinaryBundle
/// by grouping wires together according to the size of the element being bundled.
pub fn wires_to_bundle<F>(x: &[F::Item], size: usize) -> Vec<BinaryBundle<F::Item>>
where
    F: FancyReveal + Fancy + FancyBinary,
{
    x.chunks(size)
        .map(|x_chunk| BinaryBundle::new(x_chunk.to_vec()))
        .collect()
}

/// Obliviously unmasks data by subtracting each mask from each element
pub fn fancy_unmask<F>(
    f: &mut F,
    elements: &[BinaryBundle<F::Item>],
    masks: &[BinaryBundle<F::Item>],
) -> Result<Vec<BinaryBundle<F::Item>>, F::Error>
where
    F: FancyReveal + Fancy + FancyBinary,
{
    let mut res = Vec::new();

    for i in 0..elements.len() {
        res.push(f.bin_xor(&elements[i], &masks[i])?);
    }
    Ok(res)
}
