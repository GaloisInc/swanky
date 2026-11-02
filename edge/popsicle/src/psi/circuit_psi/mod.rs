//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).
use crate::{
    circuit_psi::{
        base_psi::BasePsi,
        circuits::{IntersectionBitVector, Unmask},
    },
    psi::circuit_psi::circuits::wires_to_bundle,
};
use core::marker::PhantomData;
use fancy_traits::{BinaryBundle, Circuit, FancyBinary, FancyEncode, FancyReceive};
use rand::{CryptoRng, SeedableRng};
use swanky_block::Block512;
use swanky_channel::Channel;
use swanky_error::ErrorKind;
use swanky_field_binary::F2;

pub mod base_psi;
pub mod circuits;
pub mod tests;
pub mod utils;

/// The type of set primary keys to be used
pub type PrimaryKey = Vec<u8>;

/// The type of payloads to be used
pub type Payload = Block512;
/// The number of bytes representing a set primary key.
pub const PRIMARY_KEY_SIZE: usize = 8;
/// The number of bytes representing a payload value.
pub const PAYLOAD_SIZE: usize = 8;

/// Encoded Garbled Circuit PsiInputs
pub struct CircuitInputs<F> {
    /// The sender's primary keys wires
    pub sender_primary_keys: Vec<F>,
    /// The receiver's primary keys wires
    pub receiver_primary_keys: Vec<F>,
    /// In psty, the sender's payload's are masked
    /// or alternatively one-time padded
    pub sender_payloads_masked: Vec<F>,
    /// The receiver payloads wires
    pub receiver_payloads: Vec<F>,
    /// The receiver gets the correct masks/one time pads
    /// when they share the same key with the sender
    /// and otherwise receive a random mask
    pub masks: Vec<F>,
}

/// Encoded Garbled Circuit PsiInputs
#[derive(Default)]
pub struct PrivateIntersectionPayloads<F> {
    /// The sender's unmasked payloads wires
    pub sender_payloads: Vec<BinaryBundle<F, { PAYLOAD_SIZE * 8 }>>,
    /// The receiver payloads wires
    pub receiver_payloads: Vec<BinaryBundle<F, { PAYLOAD_SIZE * 8 }>>,
}

/// Encoded Garbled Circuit PsiInputs
#[derive(Default)]
pub struct PrivateIntersection<F> {
    /// The bit vector that indicates whether
    /// a set primary key is in the intersection or not
    pub existence_bit_vector: Vec<F>,
    /// The sender set primary keys wires
    pub primary_keys: Vec<BinaryBundle<F, { PRIMARY_KEY_SIZE * 8 }>>,
}

/// A struct defining the intersection results, i.e. the bit vector
/// that shows whether a primary key is in the intersection and the
/// unmasked payloads in Circuit Psi
pub struct Intersection<T> {
    /// The set of primary keys and intersection bit vector
    pub intersection: PrivateIntersection<T>,
    /// The unmasked payloads
    pub payloads: PrivateIntersectionPayloads<T>,
}

/// A circuit that takes a [`CircuitInputs`] as input and groups
/// the wires of its different parts into [`BinaryBundle`]s.
///
/// For instance, `sender_payloads`'s wires are grouped according to the set
/// primary key size. This function allows us to reason about circuit inputs not
/// in terms of individual wires, but rather in terms of the values that they
/// represent.
#[derive(Default)]
pub(crate) struct BundlePayloads<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for BundlePayloads<'a>
where
    F::Item: 'a,
{
    type Input = &'a CircuitInputs<F::Item>;
    type Output = (
        Vec<BinaryBundle<F::Item, { PAYLOAD_SIZE * 8 }>>,
        Vec<BinaryBundle<F::Item, { PAYLOAD_SIZE * 8 }>>,
    );

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Output> {
        let sender_payloads = Unmask::default().execute(
            backend,
            (
                &wires_to_bundle::<F, { PAYLOAD_SIZE * 8 }>(&inputs.sender_payloads_masked),
                &wires_to_bundle::<F, { PAYLOAD_SIZE * 8 }>(&inputs.masks),
            ),
            channel,
        )?;
        let receiver_payloads =
            wires_to_bundle::<F, { PAYLOAD_SIZE * 8 }>(&inputs.receiver_payloads);

        Ok((sender_payloads, receiver_payloads))
    }
}

/// Computes the Circuit PSI on the parties' inputs (with payloads).
///
/// self: The parties' internal state.
/// primary_keys: The parties' set primary keys that we perform the intersection
///      operation on (see example below).
/// payloads: The payloads associated with primary keys of the intersection
///           (e.g. incomes associated with id's that we are intersecting
///             on).
///           Payloads are optional, and this function allows computing
///           on set primary keys alone (see example below).
///
/// example:
/// ---------------------------------------
/// primary key (`primary_keys`) | data (`payloads`)
/// ---------------------------------------
/// 0                   | ("GOOG", $22)
/// 1                   | ("AMZN", $47)
/// 2                   | ("META", $92)
/// ...
///
/// The protocol works as follows:
/// (0) Check that the set of primary keys has the same size as the set of payloads
/// if the latter is not empty.
/// (1) Call the Base Psi to create the circuit's input.
/// The Base Psi effectively constructs the intersection in a hidden form
/// that only the garbled circuit can read and operate on.
/// (2) Turns the circuit inputs into bundles that are easier to operate on in swanky's
/// fancy garbling.
/// (3) Takes the output of the Base Psi and turns it into a garbled intersection bit
/// vector which indicates the presence or abscence of a primary key.
/// (4) Computes the user defined circuit on the parties' inputs.
pub fn intersect_with_payloads<
    F: FancyBinary + FancyEncode<F2> + FancyReceive<F2>,
    B: BasePsi,
    RNG: CryptoRng + SeedableRng,
>(
    backend: &mut F,
    primary_keys: &[PrimaryKey],
    payloads: Option<&[Payload]>,
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<Intersection<F::Item>> {
    // (0)
    if let Some(payloads) = payloads
        && primary_keys.len() != payloads.len()
    {
        swanky_error::bail!(
            ErrorKind::OtherError,
            "Failed to intersect due to incomplete payload set: (#payloads := {}) != (#primary keys := {})",
            payloads.len(),
            primary_keys.len(),
        );
    }
    // (1)
    let circuit_inputs = B::base_psi(backend, primary_keys, payloads, channel, rng)?;
    // (2)
    let primary_keys =
        wires_to_bundle::<F, { PRIMARY_KEY_SIZE * 8 }>(&circuit_inputs.sender_primary_keys);
    let (sender_payloads, receiver_payloads) =
        BundlePayloads::default().execute(backend, &circuit_inputs, channel)?;

    // (3)
    let existence_bit_vector = IntersectionBitVector::default().execute(
        backend,
        (
            &circuit_inputs.sender_primary_keys,
            &circuit_inputs.receiver_primary_keys,
        ),
        channel,
    )?;
    let intersection_results = Intersection {
        intersection: PrivateIntersection {
            existence_bit_vector,
            primary_keys,
        },
        payloads: PrivateIntersectionPayloads {
            sender_payloads,
            receiver_payloads,
        },
    };
    Ok(intersection_results)
}

/// Computes the Circuit PSI on the parties' inputs with no payloads.
pub fn intersect<
    F: FancyBinary + FancyEncode<F2> + FancyReceive<F2>,
    B: BasePsi,
    RNG: CryptoRng + SeedableRng,
>(
    backend: &mut F,
    keys: &[PrimaryKey],
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<Intersection<F::Item>> {
    intersect_with_payloads::<F, B, RNG>(backend, keys, None, channel, rng)
}
