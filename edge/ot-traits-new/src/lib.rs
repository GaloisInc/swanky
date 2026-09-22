#![deny(missing_docs)]
//! Base traits for Oblivious Transfer protocols

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;
use swanky_party::either::PartyEither;
use swanky_rng::SwankyRng;
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
    fn init(rng: &mut SwankyRng, channel: &mut Channel) -> Result<Self>;
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
        rng: &mut SwankyRng,
        channel: &mut Channel,
    ) -> Result<Self>
    where
        I::IntoIter: ExactSizeIterator;
}
