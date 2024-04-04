//! Various fancy circuits
use crate::{circuit_psi::*, errors::Error};
use fancy_garbling::{BinaryBundle, BinaryGadgets, Fancy, FancyBinary, FancyReveal};
use itertools::Itertools;
use std::fmt::Debug;

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

/// Fancy function which computes the cardinality of the intersection
pub fn fancy_cardinality<F, E>() -> impl FnMut(
    &mut F,
    &[<F as Fancy>::Item],
    &[BinaryBundle<<F as Fancy>::Item>],
) -> Result<BinaryBundle<<F as Fancy>::Item>, Error>
where
    F: FancyBinary + FancyReveal + Fancy<Item = AllWire, Error = E>,
    E: Debug,
    Error: From<E>,
{
    |f, intersect_bitvec, _| {
        let mut acc = f.bin_constant_bundle(0, ELEMENT_SIZE * 8)?;
        let one = f.bin_constant_bundle(1, ELEMENT_SIZE * 8)?;
        let zero = f.bin_constant_bundle(0, ELEMENT_SIZE * 8)?;
        for bit in intersect_bitvec {
            let mux = f.bin_multiplex(bit, &zero, &one)?;
            acc = f.bin_addition_no_carry(&acc, &mux)?;
        }
        Ok(acc)
    }
}

/// Fancy function which computes the payload sum of the intersection
/// where associated payloads with elements of the intersection are summed
/// together and returned
pub fn fancy_payload_sum<F, E>() -> impl FnMut(
    &mut F,
    &[<F as Fancy>::Item],
    &[BinaryBundle<<F as Fancy>::Item>],
    Vec<BinaryBundle<<F as Fancy>::Item>>,
    Vec<BinaryBundle<<F as Fancy>::Item>>,
) -> Result<BinaryBundle<<F as Fancy>::Item>, Error>
where
    F: FancyBinary + FancyReveal + Fancy<Item = AllWire, Error = E>,
    E: Debug,
    Error: From<E>,
{
    |f, intersect_bitvec, _, payload_a, payload_b| {
        let mut acc = f.bin_constant_bundle(0, PAYLOAD_SIZE * 8)?; // multiplication extends the representation of the number
        let zero = f.bin_constant_bundle(0, PAYLOAD_SIZE * 8)?;

        for (i, bit) in intersect_bitvec.into_iter().enumerate() {
            let mux_a = f.bin_multiplex(bit, &zero, &payload_a[i])?;
            let mux_b = f.bin_multiplex(bit, &zero, &payload_b[i])?;
            let mul = f.bin_addition_no_carry(&mux_a, &mux_b)?;
            acc = f.bin_addition_no_carry(&acc, &mul)?;
        }
        Ok(acc)
    }
}
