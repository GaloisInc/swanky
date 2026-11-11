#![deny(missing_docs)]
//! Implementation of an insecure OT protocol for testing purposes

use std::marker::PhantomData;

use rand::{CryptoRng, RngExt};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{OTInit, OTRandom, Party, Receiver, WhichParty};
use swanky_party::{either::PartyEither, private::PartyPrivate};
use vectoreyes::U8x16;

/// Dummy OT protocol.
///
/// This implementation intentionally does not have desirable
/// properties of an OT protocol; in particular, the choice bit is
/// revealed to the `Sender`.
pub struct Dummy<P: Party>(PhantomData<P>);

impl<P: Party> OTInit<P> for Dummy<P> {
    fn init(_channel: &mut Channel, _rng: &mut impl CryptoRng) -> Result<Self> {
        Ok(Self(PhantomData))
    }
}

impl<P: Party> OTRandom<P> for Dummy<P> {
    fn ot_random<O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        &mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        for input in inputs.map(|sz| std::iter::repeat_n((), sz), |i| i.iter().copied()) {
            let b: PartyPrivate<Receiver, P, _> = input.into();
            let b = channel.communicate(b.into())?;

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let (k0, k1) = (rng.random::<U8x16>(), rng.random::<U8x16>());

                    let k =
                        ConditionallySelectable::conditional_select(&k1, &k0, b.ct_eq(&F2::ZERO));
                    channel.write(&k)?;

                    outputs.extend(std::iter::once(PartyEither::new(ev, [k0, k1])));
                }
                WhichParty::Receiver(ev) => {
                    let k = channel.read::<U8x16>()?;
                    outputs.extend(std::iter::once(PartyEither::new(ev, k)));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_ot_traits_new::Sender;

    #[test]
    fn test_random_functionality() {
        swanky_ot_test_new::test_rotext::<Dummy<Sender>, Dummy<Receiver>>(128);
    }

    #[test]
    fn test_standard_functionality() {
        swanky_ot_test_new::test_otext::<Dummy<Sender>, Dummy<Receiver>>(128);
    }
}
