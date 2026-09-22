#![deny(missing_docs)]
//! Base traits for Oblivious Transfer protocols

swanky_party::party_system! {
    pub mod party {
        /// The sender in an OT protocol.
        Sender,
        /// The receiver in an OT protocol.
        Receiver,
    }
}

pub use party::*;
