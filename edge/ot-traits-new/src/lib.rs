#![deny(missing_docs)]
//! Base traits for 1-out-of-2 _oblivious transfer_ protocols.
//!
//! Oblivious transfer (OT) protocols allow a sender to transfer one
//! of some number of pieces of information to a receiver while
//! remaining oblivious to which piece of information was transferred.
//! Furthermore, the receiver does not get to learn anything about the
//! information that _wasn't_ transferred.
//!
//! OT is _complete_ for secure multi-party computation: Given an
//! implementation of OT, any poly-time computable function can be
//! securely evaluated without additional primitives.
//!
//! The traits in this module define the structure of any 1-out-of-2
//! (that is: 1 message out of 2 possible messages) OT protocol.
//! The [`swanky_party`] crate is used to enforce privacy boundaries
//! on the various components at the type level, so that OT senders
//! can never access information private to OT receivers (and
//! vice-versa).

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
pub trait OTInit<P: Party>: Sized {
    /// Initialize and return an OT protocol.
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self>;
}

/// OT protocols where the messages are random, but _correlated_ via
/// $`\Delta`$ (which gives the offset between the zero and one
/// message).
///
/// In this setting, the [`Sender`] only has to keep track of _one_
/// set of random outputs, since the second set can be recovered using
/// the $`\Delta`$ value.
pub trait OTCorrelated<P: Party>: OTInit<P> {
    /// Run correlated OT.
    ///
    /// Note that protocols implementing this method typically require
    /// some 'preliminary' OT where the roles of [`Sender`] and
    /// [`Receiver`] are switched (i.e. an [`OTCorrelated`] `Sender`
    /// must temporarily act as some [`ObliviousTransfer`] `Receiver`,
    /// and vice-versa).
    /// When implementing this functionality,
    /// [`swanky_party::OppositeParty`] may be useful.
    fn ot_correlated<I: IntoIterator<Item = F2>, O: Extend<PartyEither<P, U8x16, U8x16>>>(
        self,
        inputs: PartyEither<P, usize, I>,
        delta: PartyPrivate<P, Sender, U8x16>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self>
    where
        I::IntoIter: ExactSizeIterator;
}

/// OT protocols where the messages are random.
///
/// 'Standard' 1-out-of-2 protocols (see [`ObliviousTransfer`]) can be
/// constructed using protocols implementing this trait via a standard
/// construction.
/// For the sake of discussion, assume the [`Receiver`] has a
/// selection bit $`c`$, the [`Sender`] has messages $`m_0`$ and
/// $`m_1`$, and the `Receiver` wants to learn $`m_c`$.
///
/// 1. Run [`OTRandom::ot_random`] with the given selection bit.
///    The `Sender` generates and saves two values, $`x_0`$ and
///    $`x_1`$, the `Receiver` learns $`x_c`$.
/// 2. `Sender` computes and sends $`\text{Enc}_{x_0}(m_0)`$ and
///    $`\text{Enc}_{x_1}(m_1)`$.
///    $`\text{Enc}`$ is agreed upon ahead of time.
/// 3. `Receiver` can only decrypt the message encrypted with $`x_c`$,
///    which is $`m_c`$.
pub trait OTRandom<P: Party>: OTInit<P> {
    /// Run random OT.
    ///
    /// The `inputs` and `outputs` are party-specific: The [`Sender`]
    /// provides the number of selections, and receives the pairs of
    /// generated messages (as arrays of length 2).
    /// The [`Receiver`] provides the selection bits, and receives the
    /// messages that they selected (i.e. the entries in the pairs
    /// generated on the `Sender` side corresponding to their
    /// selection bits).
    fn ot_random<I: IntoIterator<Item = F2>, O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
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
/// - `Receiver` learns $`M_b`$
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
