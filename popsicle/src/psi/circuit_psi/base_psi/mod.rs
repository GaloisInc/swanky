//! The base psi computation that pre-processes the party's
//! inputs prior to calling the circuit in the circuit psi
use crate::{circuit_psi::*, errors::Error};
use fancy_garbling::{AllWire, FancyInput};
use rand::{CryptoRng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block512};
use std::fmt::Debug;

// The number of hash functions that will be used to attempt to
// place any item in a cuckoo bin
const NHASHES: usize = 3;

/// The `OpprfReceiver` which implement BasePsi
pub mod receiver;

/// The `OpprfSender` which implement BasePsi
pub mod sender;

/// A trait which describes the party's behavior in circuit psi
/// prior to calling the actual garbled circuit. The BasePsi could
/// be thought of as a pre-processing stage for efficiency purposes.
///
/// The `BasePsi`'s primary function is to manipulate each party's input
/// in order to make the eventual computation in the garbled circuit
/// and specifically the garbled intersection more efficient.
/// For example in PSTY19, the BasePsi allows the parties to only perform a
/// linear number of secure comparisons to find the intersection instead of
/// quadratically many (i.e. the number of comparisons needed if everything was
/// performed in the garbled circuit with no a-priori pre-processing computation).
pub trait BasePsi {
    /// Initializes the BasePsi party
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG, has_payload: bool) -> Result<Self, Error>
    where
        Self: Sized,
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng;
    /// Parties locally hash their inputs
    ///
    /// This allows them to agree on an ordering of their inputs.
    fn hash_data<C, RNG>(
        &mut self,
        set: &[Vec<u8>],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng;
    /// Parties call an OPPRF on their inputs
    ///
    /// This allows them to agree on a hidden representation of
    /// their shared inputs that they can only reveal and operate on
    /// in a garbled circuit. This additionally allows them to mask
    /// their payloads so that only payloads associated with intersection
    /// are kept in the garbled circuit.
    fn opprf_exchange<C, RNG>(&mut self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng;
    /// Parties turn their inputs into garbled wires
    fn encode_circuit_inputs<F, E>(
        &mut self,
        gc_party: &mut F,
    ) -> Result<CircuitInputs<F::Item>, Error>
    where
        F: FancyInput<Item = AllWire, Error = E>,
        E: Debug,
        Error: From<E>;
    /// A wrapper that calls the different pieces of the BasePsi in order
    /// to the necessary hidden inputs that the CircuitPsi can operate on.
    fn base_psi<F, E, C, RNG>(
        gc_party: &mut F,
        set: &[Vec<u8>],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<CircuitInputs<F::Item>, Error>
    where
        Self: Sized,
        F: FancyInput<Item = AllWire, Error = E>,
        E: Debug,
        Error: From<E>,
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        let mut has_payloads = false;
        if !payloads.is_empty() {
            has_payloads = true;
        }
        let mut party = Self::init(channel, rng, has_payloads)?;
        party.hash_data(set, payloads, channel, rng)?;

        channel.flush()?;
        party.opprf_exchange(channel, rng)?;
        channel.flush()?;

        party.encode_circuit_inputs(gc_party)
    }
}
