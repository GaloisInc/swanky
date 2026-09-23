//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).
use crate::psi::circuit_psi::{base_psi::*, circuits::*};
use fancy_circuits::BinaryBundle;
use fancy_garbling::WireMod2;
use fancy_traits::{Fancy, FancyBinary};
use rand::{CryptoRng, SeedableRng};
use swanky_block::Block512;
use swanky_channel::Channel;

pub mod base_psi;
pub mod circuits;
pub mod evaluator;
pub mod garbler;
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
pub struct PrivateIntersectionPayloads<F> {
    /// The sender's unmasked payloads wires
    pub sender_payloads: Vec<BinaryBundle<F>>,
    /// The receiver payloads wires
    pub receiver_payloads: Vec<BinaryBundle<F>>,
}

impl<F> Default for PrivateIntersectionPayloads<F> {
    fn default() -> Self {
        PrivateIntersectionPayloads {
            sender_payloads: vec![],
            receiver_payloads: vec![],
        }
    }
}

/// Encoded Garbled Circuit PsiInputs
pub struct PrivateIntersection<F> {
    /// The bit vector that indicates whether
    /// a set primary key is in the intersection or not
    pub existence_bit_vector: Vec<F>,
    /// The sender set primary keys wires
    pub primary_keys: Vec<BinaryBundle<F>>,
}

impl<F> Default for PrivateIntersection<F> {
    fn default() -> Self {
        PrivateIntersection {
            existence_bit_vector: vec![],
            primary_keys: vec![],
        }
    }
}

/// A struct defining the intersection results, i.e. the bit vector
/// that shows whether a primary key is in the intersection and the
/// unmasked payloads in Circuit Psi
pub struct Intersection {
    /// The set of primary keys and intersection bit vector
    pub intersection: PrivateIntersection<WireMod2>,
    /// The unmasked payloads
    pub payloads: PrivateIntersectionPayloads<WireMod2>,
}

/// A function that takes a `CircuitInputs`` (created by a BasePsi) and groups the wires of
/// its different parts into `BinaryBundle` for ease of use in a fancy garbled circuit.
///
/// For instance, `sender_payloads`'s wires are grouped according to the set primary key size.
/// This function allows us to reason about circuit inputs not in terms of individual wires, but
/// rather in terms of the values that they represent.
fn bundle_payloads<F>(
    f: &mut F,
    circuit_inputs: &CircuitInputs<F::Item>,
    channel: &mut Channel,
) -> swanky_error::Result<(
    Vec<BinaryBundle<<F as Fancy>::Item>>,
    Vec<BinaryBundle<<F as Fancy>::Item>>,
)>
where
    F: FancyBinary + Fancy<Item = WireMod2>,
{
    let sender_payloads = fancy_unmask(
        f,
        &wires_to_bundle::<F>(&circuit_inputs.sender_payloads_masked, PAYLOAD_SIZE * 8),
        &wires_to_bundle::<F>(&circuit_inputs.masks, PAYLOAD_SIZE * 8),
        channel,
    )?;
    let receiver_payloads =
        wires_to_bundle::<F>(&circuit_inputs.receiver_payloads, PAYLOAD_SIZE * 8);

    Ok((sender_payloads, receiver_payloads))
}

fn bundle_primary_keys<F>(
    circuit_inputs: &CircuitInputs<F::Item>,
) -> swanky_error::Result<Vec<BinaryBundle<<F as Fancy>::Item>>>
where
    F: FancyBinary + Fancy<Item = WireMod2>,
{
    Ok(wires_to_bundle::<F>(
        &circuit_inputs.sender_primary_keys,
        PRIMARY_KEY_SIZE * 8,
    ))
}
/// A trait which describes the parties participating in the circuit
/// PSI protocol along with their functionality.
///
/// This trait is implemented by the two parties participating
/// in the protocol,i.e the CircuitPsi Garbler and the Evaluator.
pub trait CircuitPsi {
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
    // primary key (`primary_keys`) | data (`payloads`)
    // ---------------------------------------
    // 0                   | ("GOOG", $22)
    // 1                   | ("AMZN", $47)
    // 2                   | ("META", $92)
    // ...
    fn intersect_with_payloads(
        &mut self,
        primary_keys: &[PrimaryKey],
        payloads: Option<&[Payload]>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Intersection>;
    /// Computes the Circuit PSI on the parties' inputs with no payloads.
    fn intersect(
        &mut self,
        keys: &[PrimaryKey],
        channel: &mut Channel,
    ) -> swanky_error::Result<Intersection>;
}
