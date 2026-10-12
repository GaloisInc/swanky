#![deny(missing_docs)]
//! Implementation of the Chou-Orlandi oblivious transfer protocol
//! (cf. <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve
//! group from the `curve25519-dalek` crate, and works over 128-bit
//! blocks rather than arbitrary-length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if
//! the value `x^i` produced by the receiver is not randomized, all
//! the random-OTs produced by the protocol will be the same.
//! We fix this by hashing in `i` during the key derivation phase.

use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoBasepointTable,
};
use rand::CryptoRng;
use subtle::{ConditionallySelectable, ConstantTimeEq};

use swanky_adversary::{Malicious, SemiHonest};
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{OTInit, OTRandom, Party, Receiver, Sender, WhichParty};
use swanky_party::{
    either::PartyEither,
    private::{PartyPrivate, PartyPrivateCopy},
};
use vectoreyes::U8x16;

fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> U8x16 {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    U8x16::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).expect("The slice is exactly 16 bytes"))
}

/// The Chou-Orlandi (random) OT protocol.
///
/// See the module-level documentation for more information / the
/// paper this implementation is based on.
pub struct ChouOrlandi<P: Party> {
    counter: u128,
    y: PartyPrivateCopy<Sender, P, Scalar>,
    ys: PartyPrivateCopy<Sender, P, RistrettoPoint>,
    s: PartyPrivate<Receiver, P, RistrettoBasepointTable>,
}

impl<P: Party> OTInit<P> for ChouOrlandi<P> {
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> swanky_error::Result<Self> {
        let y = PartyPrivateCopy::new_with(|| Scalar::random(rng));
        let s = channel.communicate(y.map(|y| &y * RISTRETTO_BASEPOINT_TABLE))?;

        Ok(Self {
            counter: 0,
            y,
            ys: y.map(|y| y * s),
            s: PartyPrivate::new_with(|| RistrettoBasepointTable::create(&s)),
        })
    }
}

impl<P: Party> OTRandom<P> for ChouOrlandi<P> {
    fn ot_random<O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> swanky_error::Result<Self> {
        let zero = self.s.as_ref().map(|s| &Scalar::ZERO * s);
        let one = self.s.as_ref().map(|s| &Scalar::ONE * s);

        for input in inputs.map(|sz| std::iter::repeat_n((), sz), |i| i.iter()) {
            self.counter += 1;

            let input: PartyPrivate<Receiver, P, _> = input.into();
            let x: PartyPrivate<Receiver, P, _> = PartyPrivate::new_with(|| Scalar::random(rng));
            let r = channel.communicate(
                input
                    .zip(x.as_ref())
                    .zip(zero.as_ref())
                    .zip(one.as_ref())
                    .map(|(((input, x), zero), one)| {
                        let c = ConditionallySelectable::conditional_select(
                            one,
                            zero,
                            input.ct_eq(&F2::ZERO),
                        );
                        c + x * RISTRETTO_BASEPOINT_TABLE
                    })
                    .into(),
            )?;

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let yr = self.y.into_inner(ev) * r;

                    let k0 = hash_pt(self.counter, &yr);
                    let k1 = hash_pt(self.counter, &(yr - self.ys.into_inner(ev)));

                    outputs.extend(std::iter::once(PartyEither::new(ev, [k0, k1])));
                }
                WhichParty::Receiver(ev) => {
                    outputs.extend(std::iter::once(PartyEither::new(
                        ev,
                        hash_pt(
                            self.counter,
                            &(x.as_ref().into_inner(ev) * self.s.as_ref().into_inner(ev)),
                        ),
                    )));
                }
            }
        }

        Ok(self)
    }
}

impl<P: Party> SemiHonest for ChouOrlandi<P> {}
impl<P: Party> Malicious for ChouOrlandi<P> {}

#[test]
fn test_random_functionality() {
    swanky_ot_test_new::test_rotext::<ChouOrlandi<Sender>, ChouOrlandi<Receiver>>(128);
}

#[test]
fn test_standard_functionality() {
    swanky_ot_test_new::test_otext::<ChouOrlandi<Sender>, ChouOrlandi<Receiver>>(128);
}
