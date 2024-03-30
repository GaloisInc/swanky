//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).
use crate::errors::Error;
use fancy_garbling::BinaryBundle;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

pub mod circuits;
pub mod evaluator;
pub mod garbler;

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
    type Item; //
    type F; // implements FancyBinary (i.e. Garbler or Evaluator)

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
        set: &[Vec<u8>],
        payloads: Option<&[Block512]>,
        channel: &mut C,
        rng: &mut RNG,
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
