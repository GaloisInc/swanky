//! Various fancy circuits
use crate::circuit_psi::{PAYLOAD_SIZE, PRIMARY_KEY_SIZE};
use core::marker::PhantomData;
use fancy_circuits::binary::{AddNoCarry, Eq, Mux, PairwiseXor};
use fancy_traits::{BinaryBundle, Circuit, Fancy, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 8;

/// Fancy circuit to compute the intersection of two sets
/// and return a bit vector indicating the presence or absence of
/// set elements.
///
/// The sender and receiver slices are assumed to be of the same size
/// and ordered in such a way that if elements are shared between them
/// then they will be in the same position.
pub(crate) struct IntersectionBitVector<'a>(PhantomData<&'a ()>);

impl<'a> IntersectionBitVector<'a> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'a, F: FancyBinary> Circuit<F> for IntersectionBitVector<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (sender_inputs, receiver_inputs) = inputs;
        assert_eq!(sender_inputs.len(), receiver_inputs.len());

        sender_inputs
            .chunks(HASH_SIZE * 8)
            .zip(receiver_inputs.chunks(HASH_SIZE * 8))
            .map(|(xs, ys)| {
                Eq::<{ HASH_SIZE * 8 }>::default().execute(
                    backend,
                    (
                        &BinaryBundle::new(
                            xs.to_vec()
                                .try_into()
                                .expect("vector should be of length `HASH_SIZE * 8`"),
                        ),
                        &BinaryBundle::new(
                            ys.to_vec()
                                .try_into()
                                .expect("vector should be of length `HASH_SIZE * 8`"),
                        ),
                    ),
                    channel,
                )
            })
            .collect()
    }
}

/// Fancy function that turns a slice of binary wires into a vector of BinaryBundle
/// by grouping wires together according to the size of the element being bundled.
pub fn wires_to_bundle<F: Fancy, const N: usize>(x: &[F::Item]) -> Vec<BinaryBundle<F::Item, N>> {
    x.chunks(N)
        .map(|x_chunk| {
            BinaryBundle::new(
                x_chunk
                    .to_vec()
                    .try_into()
                    .expect("vector should be of length `N`"),
            )
        })
        .collect()
}

/// Obliviously unmasks data by subtracting each mask from each element.
pub(crate) struct Unmask<'a>(PhantomData<&'a ()>);

impl<'a> Unmask<'a> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'a, F: FancyBinary> Circuit<F> for Unmask<'a>
where
    F::Item: 'a,
{
    type Input = (
        &'a [BinaryBundle<F::Item, { PAYLOAD_SIZE * 8 }>],
        &'a [BinaryBundle<F::Item, { PAYLOAD_SIZE * 8 }>],
    );
    type Output = Vec<BinaryBundle<F::Item, { PAYLOAD_SIZE * 8 }>>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (elements, masks) = inputs;
        elements
            .iter()
            .zip(masks.iter())
            .map(|(element, mask)| {
                PairwiseXor::default()
                    .execute(backend, (element.wires(), mask.wires()), channel)
                    .map(|v| {
                        BinaryBundle::new(
                            v.try_into()
                                .expect("vector should be of length `PAYLOAD_SIZE * 8`"),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()
    }
}

/// Circuit to compute the cardinality of the intersection.
#[derive(Default)]
pub struct Cardinality<'a>(PhantomData<&'a ()>);

impl<'a> Cardinality<'a> {
    /// Create a new [`Cardinality`] circuit.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>> Circuit<F> for Cardinality<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = BinaryBundle<F::Item, { PRIMARY_KEY_SIZE * 8 }>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let zero = BinaryBundle::constant(backend, 0);
        let one = BinaryBundle::constant(backend, 1);
        let mut acc = zero.clone();
        for bit in inputs {
            let mux = Mux::default().execute(backend, (bit.clone(), &zero, &one), channel)?;
            acc = AddNoCarry::default().execute(backend, (&acc, &mux), channel)?;
        }
        Ok(acc)
    }
}

/// Circuit computing the payload sum of the intersection.
///
/// On input $`(I, A, B)`$, where $`I`$ is a bitvector with ones at the indicies
/// where there is an intersection, and $`A`$ and $`B`$ are the payload values of
/// each set, the circuit computes $`\sum_{i \in I} A_i + B_i`$.
#[derive(Default)]
pub struct PayloadSum<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>> Circuit<F> for PayloadSum<'a>
where
    F::Item: 'a,
{
    type Input = (
        &'a [F::Item],
        &'a [BinaryBundle<F::Item, { PRIMARY_KEY_SIZE * 8 }>],
        &'a [BinaryBundle<F::Item, { PRIMARY_KEY_SIZE * 8 }>],
    );
    type Output = BinaryBundle<F::Item, { PRIMARY_KEY_SIZE * 8 }>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (intersect_bitvec, payload_a, payload_b) = inputs;

        let zero = BinaryBundle::constant(backend, 0);
        let mut acc = zero.clone();
        let multiplex = Mux::default();

        for (i, bit) in intersect_bitvec.iter().enumerate() {
            let mux_a = multiplex.execute(backend, (bit.clone(), &zero, &payload_a[i]), channel)?;
            let mux_b = multiplex.execute(backend, (bit.clone(), &zero, &payload_b[i]), channel)?;
            let mul = AddNoCarry::default().execute(backend, (&mux_a, &mux_b), channel)?;
            acc = AddNoCarry::default().execute(backend, (&acc, &mul), channel)?;
        }
        Ok(acc)
    }
}
