#![deny(missing_docs)]
//! Implementation of the Keller-Orsini-Scholl oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2015/546>).

use rand::CryptoRng;

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{OTInit, ObliviousTransfer, Party, Receiver, Sender};
use swanky_party::{party_map::PartyMap, private::PartyPrivate};
use vectoreyes::U8x16;

/// The Keller-Orsini-Scholl (random) OT protocol.
///
/// Original paper: <https://eprint.iacr.org/2015/546>
pub struct KOS<
    P: Party,
    OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> = swanky_ot_chou_orlandi_new::ChouOrlandi<
        PartyMap<P, Receiver, Sender>,
    >,
>(IKNP<P, OT>);

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> KOS<P, OT> {
    /// Initialize the KOS protocol using a fixed key, `s_`.
    pub fn init_fixed_key(
        s_: PartyPrivate<Sender, P, U8x16>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        Ok(Self(IKNP::init_with_fixed_base_ots(s_, channel, rng)?))
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTInit<P> for KOS<P, OT> {
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self> {
        Ok(Self(IKNP::init(channel, rng)?))
    }
}
