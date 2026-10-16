#![deny(missing_docs)]
//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious
//! transfer extension protocol (cf.
//! <https://eprint.iacr.org/2016/602>, Protocol 4).

use std::marker::PhantomData;

use rand::{CryptoRng, SeedableRng};

use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field_binary::{F2, F2BitDeserializer};
use swanky_ot_traits_new::{OTInit, ObliviousTransfer, Party, Receiver, Sender, WhichParty};
use swanky_party::{
    either::PartyEither,
    party_map::{PartyMap, map_evidence_party0, map_evidence_party1},
    private::{PartyPrivate, PartyPrivateCopy},
};
use swanky_rng::SwankyRng;
use swanky_serialization::SequenceDeserializer;
use vectoreyes::U8x16;

/// The Asharov-Lindell-Schneider-Zohner (random) OT protocol.
///
/// Original paper: <https://eprint.iacr.org/2016/602>
pub struct ALSZ<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> {
    s: PartyPrivateCopy<Sender, P, [F2; 128]>,
    s_: PartyPrivateCopy<Sender, P, U8x16>,
    rngs: PartyEither<P, [SwankyRng; 128], [(SwankyRng, SwankyRng); 128]>,
    ot: PhantomData<OT>,
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> ALSZ<P, OT> {
    /// Initialize the ALSZ protocol using a fixed key, `s_`.
    pub fn init_fixed_key(
        s_: PartyPrivate<Sender, P, [u8; 16]>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let ot = OT::init(channel, rng)?;

        let s: PartyPrivateCopy<Sender, _, _> = s_
            .as_ref()
            .map(|s_| {
                Ok(<[F2; 128]>::try_from(
                    F2BitDeserializer::new(&mut std::io::empty())
                        .wrap_err(
                            ErrorKind::SerializationError,
                            "Could not initialize bit deserializer",
                        )?
                        .read_vec(&mut &s_[..], 8 * 16)
                        .wrap_err(ErrorKind::SerializationError, "Failed to read bits")?,
                )
                .expect("There are exactly 128 bits"))
            })
            .lift_result()?
            .into();

        let inputs: PartyEither<PartyMap<P, Receiver, Sender>, usize, &[F2]> = match P::WHICH {
            WhichParty::Sender(ev) => PartyEither::new::<Receiver>(
                map_evidence_party0::<P, _, _>(ev),
                s.as_ref().into_inner(ev),
            ),
            WhichParty::Receiver(ev) => {
                PartyEither::new::<Sender>(map_evidence_party1::<P, _, _>(ev), 128)
            }
        };

        let values: PartyPrivate<Sender, PartyMap<P, Receiver, Sender>, [[U8x16; 2]; 128]> =
            PartyPrivate::new_with(|| {
                [0; 128].map(|_| {
                    let mut k0 = U8x16::default();
                    let mut k1 = U8x16::default();
                    rng.fill_bytes(k0.as_mut());
                    rng.fill_bytes(k1.as_mut());
                    [k0, k1]
                })
            });

        let mut outputs: PartyPrivate<Receiver, PartyMap<P, Receiver, Sender>, Vec<U8x16>> =
            PartyPrivate::new_with(|| Vec::with_capacity(128));

        ot.ot(
            inputs,
            values.as_ref().map(|values| &values[..]),
            outputs.as_mut(),
            channel,
            rng,
        )?;

        let rngs = match P::WHICH {
            WhichParty::Sender(ev) => PartyEither::new(
                ev,
                <[U8x16; 128]>::try_from(
                    outputs.into_inner(map_evidence_party0::<P, _, _>(ev).sym()),
                )
                .expect("The Vec has exactly 128 elements")
                .map(|output| SwankyRng::from_seed(output)),
            ),
            WhichParty::Receiver(ev) => PartyEither::new(
                ev,
                values
                    .into_inner(map_evidence_party1::<P, _, _>(ev).sym())
                    .map(|ks| (SwankyRng::from_seed(ks[0]), SwankyRng::from_seed(ks[1]))),
            ),
        };

        Ok(Self {
            s,
            s_: s_.map(|s_| U8x16::from_array(s_)).into(),
            rngs,
            ot: PhantomData,
        })
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTInit<P> for ALSZ<P, OT> {
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self> {
        let mut s_: PartyPrivate<Sender, P, _> = PartyPrivate::new([0u8; 16]);
        s_.as_mut().map(|s_| rng.fill_bytes(s_));
        ALSZ::init_fixed_key(s_, channel, rng)
    }
}
