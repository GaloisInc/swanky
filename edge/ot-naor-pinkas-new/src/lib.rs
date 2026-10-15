#![deny(missing_docs)]
//! Implementation of the Naor-Pinkas oblivious transfer protocol (cf.
//! <https://dl.acm.org/citation.cfm?id=365502>).
//!
//! This implementation uses the Ristretto prime order elliptic curve
//! group from the `curve25519-dalek` library

use std::marker::PhantomData;

use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use rand::CryptoRng;

use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_adversary::SemiHonest;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{OTInit, OTRandom, Party, Receiver, Sender, WhichParty};
use swanky_party::{
    either::PartyEither,
    private::{PartyPrivate, PartyPrivateCopy},
};
use vectoreyes::U8x16;

/// Compute `$H(K, T)$`, where `$K$` is a Ristretto point and `$T$` is
/// a tweak value.
///
/// This implementation is used to fix the bug referenced in the
/// module-level documentation.
fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> U8x16 {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    U8x16::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).expect("The slice is exactly 16 bytes"))
}

/// The Naor-Pinkas (random) OT protocol.
///
/// Original paper: <https://dl.acm.org/citation.cfm?id=365502>
///
/// This protocol is based on earlier work by Bellare and Micali,
/// making a tradeoff between communication and computation that makes
/// the protocol more suitable for situations where many oblivious
/// transfers are required.
/// In contrast with the Chou-Orlandi protocol, however, Naor-Pinkas
/// is semihonest (rather than malicious) secure.
pub struct NaorPinkas<P: Party> {
    counter: u128,
    pd: PhantomData<P>,
}

impl<P: Party> OTInit<P> for NaorPinkas<P> {
    fn init(_channel: &mut Channel, _rng: &mut impl CryptoRng) -> Result<Self> {
        Ok(Self {
            counter: 0,
            pd: PhantomData,
        })
    }
}

impl<P: Party> OTRandom<P> for NaorPinkas<P> {
    fn ot_random<O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        outputs: &mut O,
        channel: &mut Channel,
        mut rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        for input in inputs.map(|sz| std::iter::repeat_n((), sz), |i| i.iter()) {
            self.counter += 1;

            let input: PartyPrivate<Receiver, P, _> = input.into();

            let c = channel.communicate::<Sender, P, _>(PartyPrivateCopy::new_with(|| {
                RistrettoPoint::random(&mut rng)
            }))?;

            let k: PartyPrivate<Receiver, P, _> =
                PartyPrivate::new_with(|| Scalar::random(&mut rng));
            let pk0 = channel.communicate(
                input
                    .zip(k.as_ref())
                    .map(|(input, k)| {
                        let pk = k * RISTRETTO_BASEPOINT_TABLE;
                        let pk_ = c - pk;
                        ConditionallySelectable::conditional_select(
                            &pk_,
                            &pk,
                            input.ct_eq(&F2::ZERO),
                        )
                    })
                    .into(),
            )?;
            let pk = (pk0, c - pk0);

            let r: PartyPrivateCopy<Sender, P, _> =
                PartyPrivateCopy::new_with(|| Scalar::random(&mut rng));
            let ei0 = channel.communicate(r.map(|r| &r * RISTRETTO_BASEPOINT_TABLE))?;

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let k0 = hash_pt(self.counter, &(pk.0 * r.into_inner(ev)));
                    let k1 = hash_pt(self.counter, &(pk.1 * r.into_inner(ev)));

                    outputs.extend(std::iter::once(PartyEither::new(ev, [k0, k1])));
                }
                WhichParty::Receiver(ev) => outputs.extend(std::iter::once(PartyEither::new(
                    ev,
                    hash_pt(self.counter, &(ei0 * k.as_ref().into_inner(ev))),
                ))),
            }
        }

        Ok(self)
    }
}

impl<P: Party> SemiHonest for NaorPinkas<P> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_functionality() {
        swanky_ot_test_new::test_rotext::<NaorPinkas<Sender>, NaorPinkas<Receiver>>(128);
    }

    #[test]
    fn test_standard_functionality() {
        swanky_ot_test_new::test_otext::<NaorPinkas<Sender>, NaorPinkas<Receiver>>(128);
    }
}
