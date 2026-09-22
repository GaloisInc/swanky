#![deny(missing_docs)]
//! Base traits for Oblivious Transfer protocols

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

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
