//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).
use crate::{
    errors::Error,
    psi::circuit_psi::{base_psi::*, circuits::*},
};
use fancy_garbling::{AllWire, BinaryBundle, Fancy, FancyBinary, FancyReveal};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};
use std::fmt::Debug;

pub mod base_psi;
pub mod circuits;
pub mod evaluator;
pub mod garbler;
pub mod utils;

/// The type of set elements to be used
pub type Element = Vec<u8>;

/// The type of payloads to be used
pub type Payload = Block512;
/// Byte representation of a set element
pub const ELEMENT_SIZE: usize = 8;

/// Byte representation of a payload value
pub const PAYLOAD_SIZE: usize = 8;

/// Encoded Garbled Circuit PsiInputs
pub struct CircuitInputs<F> {
    pub(crate) sender_set_elements: Vec<F>,
    pub(crate) receiver_set_elements: Vec<F>,
    // In psty, the sender's payload's are masked
    // or alternatively one-time padded
    pub(crate) sender_payloads_masked: Option<Vec<F>>,
    pub(crate) receiver_payloads: Option<Vec<F>>,
    // The receiver gets the correct masks/one time pads
    // when they share the same element with the sender
    // and otherwise receive a random mask
    pub(crate) masks: Option<Vec<F>>,
}

/// A function that takes a `CircuitInputs`` (created by a BasePsi) and groups the wires of
/// its different parts into `BinaryBundle` for ease of use in a fancy garbled circuit.
///
/// For instance, `sender_set_elements`'s wires are grouped according to the set element size.
/// This function allows us to reason about circuit inputs not in terms of individual wires, but
/// rather in terms of the values that they represent.
fn bundle_inputs<F, E>(
    f: &mut F,
    circuit_inputs: &CircuitInputs<F::Item>,
) -> Result<
    (
        Vec<BinaryBundle<<F as Fancy>::Item>>, // bits that parties are intersecting on
        Option<Vec<BinaryBundle<<F as Fancy>::Item>>>,
        Option<Vec<BinaryBundle<<F as Fancy>::Item>>>,
    ),
    Error,
>
where
    F: FancyBinary + FancyReveal + Fancy<Item = AllWire, Error = E>,
    E: Debug,
    Error: From<E>,
{
    let set = wires_to_bundle::<F>(&circuit_inputs.sender_set_elements, ELEMENT_SIZE * 8);

    let mut sender_payloads = None;
    let mut receiver_payloads = None;
    if let Some(p) = &circuit_inputs.sender_payloads_masked.as_ref() {
        sender_payloads = Some(fancy_unmask(
            f,
            &wires_to_bundle::<F>(p, PAYLOAD_SIZE * 8),
            &wires_to_bundle::<F>(&circuit_inputs.masks.as_ref().unwrap(), PAYLOAD_SIZE * 8),
        )?);
        receiver_payloads = Some(wires_to_bundle::<F>(
            circuit_inputs.receiver_payloads.as_ref().unwrap(),
            PAYLOAD_SIZE * 8,
        ));
    }
    Ok((set, sender_payloads, receiver_payloads))
}

/// A trait which describes the parties participating in the circuit
/// PSI protocol along with their functionality.
///
/// This trait is implemented by the two parties participating
/// in the protocol,i.e the CircuitPsi Garbler and the Evaluator.
pub trait CircuitPsi<C, RNG>
where
    C: AbstractChannel,
    RNG: RngCore + CryptoRng + SeedableRng<Seed = Block> + Rng,
{
    /// The type of wires associated with f
    type Item;
    /// Implements FancyBinary (i.e. Garbler or Evaluator)
    type F;

    /// Computes the Circuit PSI on the parties inputs.
    ///
    /// self: The parties' internal state.
    /// set: The parties' set elements that we perform the intersection
    ///      operation on.
    /// payloads: The payloads associated with elements of the intersection
    ///           (e.g. incomes associated with id's that we are intersecting
    ///             on).
    ///           Payloads are optional, and this function allows computing
    ///           on set elements alone.
    /// channel: The channel that the party uses to communicate with the other
    ///          during the Circuit Psi protocol.
    /// rng: The dedicated rng that the party can use.
    /// circuit: The circuit that the party wishes to perform on the intersection
    ///          and optionally its associated payloads.
    /// CktOut: The type of the output of the circuit.
    fn circuit_psi_psty<P, Ckt, CktOut>(
        &mut self,
        set: &[Element],
        payloads: Option<&[Payload]>,
        circuit: &mut Ckt,
    ) -> Result<CktOut, Error>
    where
        P: BasePsi, // Before computing a circuit on the intersection
        // a base psi protocol is called to:
        // (1) prepare the intersection so that set elements may remain hidden
        // (2) prepare the payloads associated with the intersection
        //     so that they may remain hidden throughout the protocol
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
        Ckt: FnMut(
            &mut Self::F,  //
            &[Self::Item], // bit vector where a bit indicates the presence/abscence of
            //  a set element in the intersection
            &[BinaryBundle<Self::Item>], // bits that parties are intersecting on
            Option<Vec<BinaryBundle<Self::Item>>>, // party A's payload
            Option<Vec<BinaryBundle<Self::Item>>>, // party B's payload
        ) -> Result<CktOut, Error>;
}
