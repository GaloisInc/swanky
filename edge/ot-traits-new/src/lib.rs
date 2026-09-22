#![deny(missing_docs)]
//! Base traits for Oblivious Transfer protocols

use rand::CryptoRng;

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;
use swanky_party::{either::PartyEither, private::PartyPrivate};
use swanky_serialization::CanonicalSerialize;
use vectoreyes::U8x16;

swanky_party::party_system! {
    pub mod party {
        /// The sender in an OT protocol.
        Sender,
        /// The receiver in an OT protocol.
        Receiver,
    }
}

pub use party::*;

/// Initialization of OT protocols.
///
/// Initialization is shared between random OT and constructions built
/// on it, so this helps reduce duplication between implementations.
pub trait OTInit<P: Party>: Sized {
    /// Initialize and return an OT protocol.
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self>;
}

/// OT protocols where the messages are random.
///
/// 1-out-of-2 protocols can be constructed using protocols
/// implementing this trait using a standard OTP construction.
pub trait RandomOT<P: Party>: OTInit<P> {
    /// Run random OT.
    ///
    /// `inputs` : For the sender, the number of input values.
    ///            For the receiver, the selection bits.
    /// `outputs`: For the sender, the pairs of encryption keys (as
    ///            arrays).
    ///            For the receiver, the selected encryption keys.
    fn random_ot<I: IntoIterator<Item = F2>, O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        self,
        inputs: PartyEither<P, usize, I>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self>
    where
        I::IntoIter: ExactSizeIterator;
}

/// 1-out-of-2 OT protocols.
///
/// The `Sender` holds two messages, $`M_0`$ and $`M_1`$.
/// The `Receiver` wants exactly one of these two messages, $`M_b`$
/// for $`b \in {0, 1}`$.
///
/// A protocol implementing this trait should guarantee:
///
/// - `Receiver` learned $`M_b`$
/// - `Receiver` learns nothing about $`M_{1 - b}`$ (i.e. the other
///   message)
/// - `Sender` learns nothing about $`b`$ (i.e. which message the
///   `Receiver` chooses)
pub trait ObliviousTransfer<P: Party>: OTInit<P> {
    /// Run OT.
    fn ot<
        I: IntoIterator<Item = F2>,
        V: IntoIterator<Item = [T; 2]>,
        T: CanonicalSerialize,
        O: Extend<T>,
    >(
        self,
        inputs: PartyPrivate<Receiver, P, I>,
        values: PartyPrivate<Sender, P, V>,
        outputs: PartyPrivate<Receiver, P, &mut O>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self>;
}
