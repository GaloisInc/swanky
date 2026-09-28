//! Various fancy circuits
use crate::circuit_psi::*;
use fancy_circuits::{
    BinaryBundle,
    binary::{BinaryAdditionNoCarry, BinaryConstant, BinaryEquality, BinaryMultiplex, PairwiseXor},
};
use fancy_traits::{Circuit, Fancy, FancyBinary, FancyBinaryConstant};
use itertools::Itertools;
use swanky_channel::Channel;

// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 8;

/// Fancy function to compute the intersection of two sets
/// and return a bit vector indicating the presence or abscence of
/// set elements.
/// The sender and receiver slices are assumed to be of the same size
/// and ordered in such a way that if elements are shared between them
/// then they will be in the same position.
pub fn fancy_intersection_bit_vector<F>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>>
where
    F: Fancy + FancyBinary,
{
    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            BinaryEquality::new().execute(
                f,
                (
                    &BinaryBundle::new(xs.to_vec()),
                    &BinaryBundle::new(ys.to_vec()),
                ),
                channel,
            )
        })
        .collect()
}

/// Fancy function that turns a slice of binary wires into a vector of BinaryBundle
/// by grouping wires together according to the size of the element being bundled.
pub fn wires_to_bundle<F>(x: &[F::Item], size: usize) -> Vec<BinaryBundle<F::Item>>
where
    F: Fancy + FancyBinary,
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
    channel: &mut Channel,
) -> swanky_error::Result<Vec<BinaryBundle<F::Item>>>
where
    F: Fancy + FancyBinary,
{
    let mut res = Vec::new();

    for i in 0..elements.len() {
        let xor =
            PairwiseXor::new().execute(f, (elements[i].wires(), masks[i].wires()), channel)?;
        res.push(BinaryBundle::new(xor));
    }
    Ok(res)
}

/// Fancy function which computes the cardinality of the intersection
pub fn fancy_cardinality<F>(
    f: &mut F,
    intersect_bitvec: &[F::Item],
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>>
where
    F: FancyBinary + FancyBinaryConstant,
{
    let zero = BinaryConstant::new(0, PRIMARY_KEY_SIZE * 8).execute(f, (), channel)?;
    let one = BinaryConstant::new(1, PRIMARY_KEY_SIZE * 8).execute(f, (), channel)?;
    let mut acc = zero.clone();
    for bit in intersect_bitvec {
        let mux = BinaryMultiplex::new().execute(f, (bit.clone(), &zero, &one), channel)?;
        acc = BinaryAdditionNoCarry::new().execute(f, (&acc, &mux), channel)?;
    }
    Ok(acc)
}

/// Fancy function which computes the payload sum of the intersection
/// where associated payloads with elements of the intersection are summed
/// together and returned
pub fn fancy_payload_sum<F>(
    f: &mut F,
    intersect_bitvec: &[F::Item],
    payload_a: &[BinaryBundle<F::Item>],
    payload_b: &[BinaryBundle<F::Item>],
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>>
where
    F: FancyBinary + FancyBinaryConstant,
{
    let zero = BinaryConstant::new(0, PRIMARY_KEY_SIZE * 8).execute(f, (), channel)?;
    let mut acc = zero.clone();
    let multiplex = BinaryMultiplex::new();

    for (i, bit) in intersect_bitvec.iter().enumerate() {
        let mux_a = multiplex.execute(f, (bit.clone(), &zero, &payload_a[i]), channel)?;
        let mux_b = multiplex.execute(f, (bit.clone(), &zero, &payload_b[i]), channel)?;
        let mul = BinaryAdditionNoCarry::new().execute(f, (&mux_a, &mux_b), channel)?;
        acc = BinaryAdditionNoCarry::new().execute(f, (&acc, &mul), channel)?;
    }
    Ok(acc)
}
