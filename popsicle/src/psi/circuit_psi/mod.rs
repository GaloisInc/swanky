//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).
use crate::{
    errors::Error,
    psi::circuit_psi::{base_psi::*, circuits::*},
};
use fancy_garbling::{BinaryBundle, Fancy, FancyBinary, FancyReveal, WireMod2};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::Block512;
use std::fmt::Debug;

pub mod base_psi;
pub mod circuits;
pub mod evaluator;
pub mod garbler;
pub mod tests;
pub mod utils;

/// The type of set elements to be used
pub type Element = Vec<u8>;

/// The type of payloads to be used
pub type Payload = Block512;
/// The number of bytes representing a set element.
pub const ELEMENT_SIZE: usize = 8;
/// The number of bytes representing a payload value.
pub const PAYLOAD_SIZE: usize = 8;

/// Encoded Garbled Circuit PsiInputs
pub struct CircuitInputs<F> {
    /// The sender set elements wires
    pub sender_set_elements: Vec<F>,
    /// The receiver set elements wires
    pub receiver_set_elements: Vec<F>,
    /// In psty, the sender's payload's are masked
    /// or alternatively one-time padded
    pub sender_payloads_masked: Vec<F>,
    /// The receiver payloads wires
    pub receiver_payloads: Vec<F>,
    /// The receiver gets the correct masks/one time pads
    /// when they share the same element with the sender
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
    /// a set element is in the intersection or not
    pub existence_bit_vector: Vec<F>,
    /// The sender set elements wires
    pub set: Vec<BinaryBundle<F>>,
}

impl<F> Default for PrivateIntersection<F> {
    fn default() -> Self {
        PrivateIntersection {
            existence_bit_vector: vec![],
            set: vec![],
        }
    }
}

/// A function that takes a `CircuitInputs`` (created by a BasePsi) and groups the wires of
/// its different parts into `BinaryBundle` for ease of use in a fancy garbled circuit.
///
/// For instance, `sender_set_elements`'s wires are grouped according to the set element size.
/// This function allows us to reason about circuit inputs not in terms of individual wires, but
/// rather in terms of the values that they represent.
fn bundle_payloads<F, E>(
    f: &mut F,
    circuit_inputs: &CircuitInputs<F::Item>,
) -> Result<
    (
        Vec<BinaryBundle<<F as Fancy>::Item>>,
        Vec<BinaryBundle<<F as Fancy>::Item>>,
    ),
    Error,
>
where
    F: FancyBinary + FancyReveal + Fancy<Item = WireMod2, Error = E>,
    E: Debug,
    Error: From<E>,
{
    let sender_payloads = fancy_unmask(
        f,
        &wires_to_bundle::<F>(&circuit_inputs.sender_payloads_masked, PAYLOAD_SIZE * 8),
        &wires_to_bundle::<F>(&circuit_inputs.masks, PAYLOAD_SIZE * 8),
    )?;
    let receiver_payloads =
        wires_to_bundle::<F>(&circuit_inputs.receiver_payloads, PAYLOAD_SIZE * 8);

    Ok((sender_payloads, receiver_payloads))
}

fn bundle_set<F, E>(
    circuit_inputs: &CircuitInputs<F::Item>,
) -> Result<Vec<BinaryBundle<<F as Fancy>::Item>>, Error>
where
    F: FancyBinary + FancyReveal + Fancy<Item = WireMod2, Error = E>,
    E: Debug,
    Error: From<E>,
{
    Ok(wires_to_bundle::<F>(
        &circuit_inputs.sender_set_elements,
        ELEMENT_SIZE * 8,
    ))
}
/// A trait which describes the parties participating in the circuit
/// PSI protocol along with their functionality.
///
/// This trait is implemented by the two parties participating
/// in the protocol,i.e the CircuitPsi Garbler and the Evaluator.
pub trait CircuitPsi {
    /// Implements FancyBinary (i.e. Garbler or Evaluator)
    type F: FancyBinary;

    /// Computes the Circuit PSI on the parties' inputs.
    ///
    /// self: The parties' internal state.
    /// set: The parties' set elements that we perform the intersection
    ///      operation on (see example below).
    /// payloads: The payloads associated with elements of the intersection
    ///           (e.g. incomes associated with id's that we are intersecting
    ///             on).
    ///           Payloads are optional, and this function allows computing
    ///           on set elements alone (see example below).
    ///
    /// example:
    /// ---------------------------------------
    // primary key (`set`) | data (`payloads`)
    // ---------------------------------------
    // 0                   | ("GOOG", $22)
    // 1                   | ("AMZN", $47)
    // 2                   | ("META", $92)
    // ...

    fn intersect<Party>(&mut self, set: &[Element], payloads: &[Payload]) -> Result<(), Error>
    where
        Party: BasePsi,
        Self: Sized;
}
